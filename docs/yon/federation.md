# Federation, SAML and SCIM routes

These routes serve inbound OpenID Connect federation, inbound SAML 2.0 and
SCIM 2.0 provisioning over HTTP through the Yon host. Read
[docs/YON.md](../YON.md) first: it explains the `Sesame-Session` header, the
`Administrator` role and the error answers that every route shares. The
protocol behaviour behind each route is described in
[docs/FEDERATION.md](../FEDERATION.md), [docs/SAML.md](../SAML.md) and
[docs/PROVISIONING.md](../PROVISIONING.md).

Every route is `POST`, takes the operation's JSON parameters as its body and
answers the operation's JSON result, in the machine protocol's shapes
(`api/machine/v1/README.md`). A body with a field the route does not declare is
refused with `400` before SESAME runs. Some answers are trimmed to what a
caller needs, as noted below.

## Routes

| Route | Operation | Who may call | Tenant isolation |
| --- | --- | --- | --- |
| `POST /api/v1/federation/provider-register` | `federation.provider_register` | an administrator, signed in within 10 minutes | the body's `tenant_id` must be the caller's tenant |
| `POST /api/v1/federation/provider-configure` | `federation.provider_configure` | an administrator, signed in within 10 minutes | as `provider-register`; SESAME then refuses a provider of another tenant (`provider_not_found`) |
| `POST /api/v1/federation/provider-get` | `federation.provider_get` | an administrator | as `provider-configure` |
| `POST /api/v1/federation/provider-disable` | `federation.provider_disable` | an administrator | as `provider-configure` |
| `POST /api/v1/federation/login-start` | `federation.login_start` | anyone, with a `redirect_uri` from `sesame.federationredirecturis` | SESAME refuses a provider outside the body's tenant |
| `POST /api/v1/federation/login-complete` | `federation.login_complete` | anyone | SESAME refuses a login outside the body's tenant (`federated_login_not_found`) |
| `POST /api/v1/saml/provider-register` | `saml.provider_register` | an administrator, signed in within 10 minutes | the body's `tenant_id` must be the caller's tenant |
| `POST /api/v1/saml/provider-get` | `saml.provider_get` | an administrator | as `provider-register`; SESAME then refuses a provider of another tenant (`saml_provider_not_found`) |
| `POST /api/v1/saml/provider-disable` | `saml.provider_disable` | an administrator | as `provider-get` |
| `POST /api/v1/saml/login-start` | `saml.login_start` | anyone, with a `consumer_url` from `sesame.samlconsumerurls` | SESAME refuses a provider outside the body's tenant |
| `POST /api/v1/saml/login-complete` | `saml.login_complete` | anyone | SESAME refuses a login outside the body's tenant (`saml_login_not_found`) |
| `POST /api/v1/scim/client-register` | `scim.client_register` | an administrator, signed in within 10 minutes | the body's `tenant_id` must be the caller's tenant |
| `POST /api/v1/scim/client-rotate-token` | `scim.client_rotate_token` | an administrator, signed in within 10 minutes | as `client-register`; SESAME then refuses a client of another tenant (`provisioning_client_not_found`) |
| `POST /api/v1/scim/client-disable` | `scim.client_disable` | an administrator | as `client-rotate-token` |
| `POST /api/v1/scim/user-create` | `scim.user_create` | a SCIM client, by its bearer token | the token decides the tenant; the body names none |
| `POST /api/v1/scim/user-get` | `scim.user_get` | a SCIM client | as `user-create` |
| `POST /api/v1/scim/user-list` | `scim.user_list` | a SCIM client | as `user-create` |
| `POST /api/v1/scim/user-patch` | `scim.user_patch` | a SCIM client | as `user-create` |
| `POST /api/v1/scim/user-deprovision` | `scim.user_deprovision` | a SCIM client | as `user-create` |
| `POST /api/v1/scim/group-create` | `scim.group_create` | a SCIM client allowed to manage groups | as `user-create` |
| `POST /api/v1/scim/group-get` | `scim.group_get` | a SCIM client allowed to manage groups | as `user-create` |
| `POST /api/v1/scim/group-list` | `scim.group_list` | a SCIM client allowed to manage groups | as `user-create` |
| `POST /api/v1/scim/group-patch` | `scim.group_patch` | a SCIM client allowed to manage groups | as `user-create` |
| `POST /api/v1/scim/group-deprovision` | `scim.group_deprovision` | a SCIM client allowed to manage groups | as `user-create` |

"Anyone" routes are `@Public` in Tachyon: they are steps of a sign-in that
starts before the person has a session. "A SCIM client" routes are also
`@Public` in Tachyon, because SESAME, not the host, authenticates the client:
see [SCIM](#scim) below.

## Why each route is guarded this way

**Provider and SCIM client administration.** Registering, configuring and
disabling an identity provider decides whose assertions a tenant trusts, and a
SCIM client can create, change and suspend a tenant's principals. These are
tenant administration, so they need the `Administrator` role, and every route
runs through `TenantCallService`: the body's `tenant_id` must equal the tenant
of the caller's session (`403 {"code":"tenant_mismatch"}` otherwise), checked
before SESAME runs. Every one of these operations also carries the tenant to
SESAME, which looks the provider or client up inside that tenant only. An
administrator who names its own tenant and another tenant's provider or client
id gets the same `404` as for an id that does not exist, and the other
tenant's record is untouched.

**Recent sign-in for trust and credential changes.** Registering or
configuring an identity provider (OIDC or SAML) changes whose assertions sign
people in, and registering a SCIM client or rotating its token mints a bearer
credential that can create and change principals. A stolen administrator
session could turn either into lasting access, so these five routes also need
a session issued within the last 10 minutes, the same rule the self-service
authenticator routes use: an older session gets
`403 {"code":"reauthentication_required"}` before the operation runs, and
nothing is registered, configured or minted. The administrator signs in again and
retries. Reading (`provider-get`) and disabling (`provider-disable`,
`client-disable`) only reduce or report trust, so an older session may still
call them.

**Federated sign-in steps.** `login-start` and `login-complete` serve people
who are not signed in yet, so they are public. Everything that makes them safe
stays in SESAME: the state, nonce and PKCE verifier are generated and stored by
the engine, the ID token or SAML assertion is verified there (signature,
issuer, audience, expiry, nonce or `InResponseTo`, recipient), and a login is
single use. A replayed, expired, forged or mismatched step is refused:

| Step | Refusal |
| --- | --- |
| OIDC `login-complete` for a login already completed | `409 {"code":"federated_login_closed"}` |
| OIDC `login-complete` after the login expired (15 minutes) | `400 {"code":"federated_login_expired"}` |
| OIDC `login-complete` with a token for another nonce, a foreign key, another audience or an expired token | `400 {"code":"assertion_rejected"}` |
| OIDC `login-complete` naming another tenant | `404 {"code":"federated_login_not_found"}` |
| OIDC or SAML `login-start` with a URL the operator did not list, or with no list configured | `400 {"code":"redirect_not_allowed"}` |
| OIDC `login-start` before the provider is configured | `409 {"code":"provider_not_configured"}` |
| SAML `login-complete` with a bad signature, another audience, an expired assertion, or an assertion already used for another login | `400 {"code":"saml_assertion_rejected"}` |
| SAML `login-complete` for a login already completed, already refused, expired or of another tenant | `404 {"code":"saml_login_not_found"}` |
| Any step for a disabled or unknown provider | `404` |

Every way an assertion can fail answers the same code. The specific reason goes
to SESAME's audit ledger, not to the caller. The answer never contains the
token, the assertion, or the engine's message.

**Where `login-start` may send the browser.** The OIDC `redirect_uri` and the
SAML `consumer_url` name where the provider delivers the authorization code or
the signed assertion, and SAML AuthnRequests are not signed, so a caller who
chose the URL could have a provider deliver another person's sign-in to them.
The public routes therefore never take the URL from the caller on trust: it
must equal, character for character, one of the URLs the operator listed (see
[Allowed redirect targets](#allowed-redirect-targets)). Any other URL, a URL
that only differs by a trailing slash, a query, letter case or an empty value,
is refused with `400 {"code":"redirect_not_allowed"}` before SESAME runs, and
no login is created.

**What `login-start` answers.** Only what a browser redirect needs.
`federation/login-start` answers `login_id`, `authorization_url` and
`expires_at`. `saml/login-start` answers `login_id`, `redirect_url`
(HTTP-Redirect binding, `RelayState` is the login id), `authn_request` and
`destination` (for the HTTP-POST binding) and `expires_at`. The PKCE verifier
and the provider's client secret are never in either answer.

### SCIM

The SCIM client presents its token the standard way:

```text
Authorization: Bearer <token>
```

The route reads the token from that header only. The request models declare
no token field, so a token in the body is refused with `400`, and a token in
the query string is ignored. The scheme is matched without regard to case. Any
other header, scheme or a missing header sends an empty token, which SESAME
refuses. The host never decides whether a token is good: it passes it to the
engine with every operation, and the engine authenticates the client, binds
the request to that client's tenant, and checks the group grant.

| Case | Answer |
| --- | --- |
| No token, another scheme, a wrong, rotated-away or disabled client's token | `401 {"code":"provisioning_denied"}` with `WWW-Authenticate: Bearer` |
| A group route for a client without `can_manage_groups` | `403 {"code":"provisioning_forbidden"}` |
| A user or group of another tenant | `404 {"code":"scim_user_not_found"}` / `scim_group_not_found` |
| A `userName` already claimed | `409 {"code":"scim_user_conflict"}` |
| A schema, filter or PATCH operation SESAME does not implement | `400 {"code":"scim_unsupported"}` |

A SCIM client's token is answered exactly twice: by `client-register` and by
`client-rotate-token`, once each. SESAME stores only a digest, so there is
nothing to read back later. No other answer carries it, and the previous token
stops working the moment a new one is minted. Do not log request headers on
the SCIM routes.

## SCIM paths and payloads

SCIM 2.0 (RFC 7644) addresses resources as `/Users`, `/Users/{id}`, `/Groups`
with `GET`, `POST`, `PATCH` and `DELETE` and `application/scim+json` bodies.
The Yon host cannot serve those paths: Tachyon accepts only lowercase letters,
digits and hyphens in a route path (`error[TY2015]: The part 'Users' of the
route path '/scim/v2/Users' may use only lowercase letters, digits and single
hyphens`). The routes above are therefore RPC routes, and the SCIM resource
travels as a JSON string:

```json
{"body": "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"userName\":\"ada@acme.example\"}"}
```

`user-get`, `user-deprovision`, `group-get` and `group-deprovision` take
`{"resource_id": "..."}`; `user-patch` and `group-patch` take `resource_id` and
`body`; `user-list` and `group-list` take optional `filter`, `start_index` and
`count`. Results are SESAME's provisioning shapes (`id`, `userName`,
`displayName`, `active`; `totalResults`, `startIndex`, `itemsPerPage`,
`Resources`). They are not complete SCIM resources: there is no `schemas` or
`meta` member.

A directory that speaks standard SCIM (Entra ID, Okta and others) therefore
needs a translating adapter in front of the host, not a path rewrite. For each
request it must:

| SCIM request | Route | Body to send |
| --- | --- | --- |
| `POST /Users` | `/api/v1/scim/user-create` | `{"body": <the request body as a string>}` |
| `GET /Users/{id}` | `/api/v1/scim/user-get` | `{"resource_id": "{id}"}` |
| `GET /Users?filter=&startIndex=&count=` | `/api/v1/scim/user-list` | `{"filter": ..., "start_index": ..., "count": ...}` |
| `PATCH /Users/{id}` | `/api/v1/scim/user-patch` | `{"resource_id": "{id}", "body": <the request body as a string>}` |
| `DELETE /Users/{id}` | `/api/v1/scim/user-deprovision` | `{"resource_id": "{id}"}` |
| the same for `/Groups` | `/api/v1/scim/group-*` | the same shapes |

The adapter passes the `Authorization` header through unchanged and never
inspects the token. It also maps answers back: the SCIM `schemas`, `meta` and
`ListResponse` envelope, `204` for a delete, and SCIM error bodies for the
codes in the table above. SESAME does not ship this adapter, and the Yon host
makes no SCIM conformance claim.

## Allowed redirect targets

The operator lists every URL a login may return to, in `server/application.json`
or a profile file:

```json
{
  "sesame": {
    "samlconsumerurls": ["https://app.example/saml/acs"],
    "federationredirecturis": ["https://app.example/federation/callback"]
  }
}
```

| Setting | Meaning |
| --- | --- |
| `sesame.samlconsumerurls` | Every `consumer_url` that `POST /api/v1/saml/login-start` accepts. Default: empty. |
| `sesame.federationredirecturis` | Every `redirect_uri` that `POST /api/v1/federation/login-start` accepts. Default: empty. |

- Matching is exact: the body's URL must equal a listed entry character for
  character. There are no wildcards, prefixes or normalisation.
- Each entry must be an absolute `https` URL with a host and no fragment
  (`#`). When any entry is not, the settings are unusable and every request
  that needs the engine answers `500` (`engine_not_configured`), as for a bad
  `sesame.binary`; nothing falls back to accepting the body's URL.
- An empty or missing list refuses every `login-start` of that kind with
  `400 {"code":"redirect_not_allowed"}`. A deployment that does not use SAML
  or OIDC federation leaves the list empty.
- The two lists are separate: a SAML consumer URL does not allow an OIDC
  redirect, and the reverse.
- These are lists, so set them in a JSON file. `ty` passes `.env` values as
  text, which is not a list, and the settings are then unusable.
- The lists are deployment-wide: every tenant and provider may use every
  listed URL. List only URLs of applications that drive the login as described
  below.

Future work: the stronger control is a per-provider allowlist that SESAME
itself stores and enforces (registered with the provider, checked by
`federation.login_start` and `saml.login_start` in the engine), so that every
host, not only this one, is bound by it and one tenant's provider cannot
return to another tenant's application. That needs an engine change, a
machine-protocol field and a stored-data migration, and is not done yet.

## SAML assertion consumer service

The identity provider posts `SAMLResponse` and `RelayState` as an HTML form to
the `consumer_url` given at `login-start`. That URL belongs to the relying
application, not to these routes, and it must be one the operator listed in
`sesame.samlconsumerurls`. The application reads the two fields,
bounds their size, and calls `POST /api/v1/saml/login-complete` with
`{"tenant_id": ..., "login_id": <RelayState>, "assertion": <SAMLResponse>}`,
passing the `SAMLResponse` through byte for byte. The answer carries a SESAME
session secret, which the application stores in its own session (for example
an `HttpOnly` cookie). SESAME's routes never set cookies, so answering the
browser's form post directly would either expose the secret to the page or
need a cookie and redirect design that does not exist yet. The obligations in
[docs/SAML.md](../SAML.md#the-hosts-obligations) still apply to the
application.

The OpenID Connect callback works the same way: the provider redirects the
browser to the application's `redirect_uri`, which must be listed in
`sesame.federationredirecturis`, and the application drives the rest of the
login.

## Not routed

| Operation | Why |
| --- | --- |
| `federation.login_exchange` | Its answer is the token request the host must send to the provider: it carries the provider's `client_secret` and the login's PKCE `code_verifier`. `login-start` is public and its `authorization_url` carries the state, so on a public route anyone could start a login, call the exchange with any code, and read the tenant's client secret. It is not offered on any guard level, and a test checks that no route of these controllers can answer a `form`, `client_secret` or `code_verifier` field. |

Completing an OpenID Connect federated login therefore needs a host that
drives SESAME directly and performs the token request itself, as
[ADR 0004](../adr/0004-federation-egress-boundary.md) describes: the Go package
`github.com/d31ma/sesame/server/packages/sesame` (`FederatedLoginExchange`),
the machine protocol (`sesame exec --loop`), or `sesame federation
login-exchange`. Through the Yon host alone, an operator can register and
disable providers, but an OpenID Connect federated login does not work at all:
the engine keeps validated provider configuration only in memory
([docs/FEDERATION.md](../FEDERATION.md), "Validated metadata is not
snapshotted"), and `ty serve` starts a new engine for every request. So
`provider-configure` answers `200`, and the next `login-start` answers
`409 provider_not_configured`. Configure providers and run OpenID Connect
federated logins through a host that keeps one engine running: the Go package
or `sesame exec --loop`.

A future design can route the whole callback: a public route that runs
`login_exchange`, sends the token request from the Yon host with the egress
protections of [docs/FEDERATION.md](../FEDERATION.md#the-hosts-obligations)
(public addresses only, no redirects, bounded size and time, TLS verification
on), passes the ID token to `login_complete`, and never answers the token
request. That makes the Yon host an egress client, so it needs its own ADR.

## Tests

`server/tests/` holds `FederationControllerTest` and `FederationLoginTest`,
`SamlControllerTest` and `SamlLoginTest`, `ScimControllerTest`,
`ScimBearerTest`, `ScimUserTest` and `ScimGroupTest`, and
`FederationRedirectAllowlistTest`, `SamlConsumerAllowlistTest` and
`AdministratorRecentSignInTest`. Each `ty test` unit is one
invocation with a 30 second deadline, so the cases are split to keep each unit
well inside it. They run against a real engine:

- OIDC: a provider configured with a discovery document and a key set the
  test generates, and an ES256 ID token signed by the test, so a whole login
  completes. Also a hostile discovery document, replay, another nonce, a
  foreign key and another tenant.
- SAML: assertions signed by the test with RSA-SHA256 over exclusive-canonical
  XML, so a whole login completes. Also replay, an assertion reused for a new
  login, another audience, an expired assertion, a forged signature that spends
  the login, and another tenant.
- Allowed redirect targets: an attacker's URL, near misses (trailing slash,
  query, letter case, empty), no list configured and a list of the other kind
  are refused with `redirect_not_allowed` and the engine is never started;
  unsafe entries (`http`, relative, no host, a fragment, empty) fail closed
  with `engine_not_configured`; a listed URL completes a whole login.
- Recent sign-in: an administrator session older than 10 minutes cannot
  register or configure an OIDC provider, register a SAML provider, or
  register or rotate a SCIM client (`reauthentication_required`, nothing
  changed, the old SCIM token still works); a 9 minute old session may rotate.
- SCIM: the token only in `Authorization: Bearer`, a missing token, another
  scheme, a rotated or disabled client, another tenant's client and users, the
  group grant, and that a token is never echoed.

`ty test` calls controllers directly, so it cannot reach the server's role
check. The `401` and `403` answers of the administrator routes, the `405` for
`federation/login-exchange`, the `WWW-Authenticate` header, the `Authorization`
header reaching the SCIM routes, and the `400` for a token in a body were
checked against `ty serve`.
