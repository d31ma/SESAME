# OAuth and OpenID Connect routes

These routes serve SESAME's OpenID provider through the Yon host. Read
[docs/YON.md](../YON.md) first: it explains the `Sesame-Session` header, the
`Administrator` role and the error answers that the administration routes
share.

The routes come in two layers:

1. **Standard endpoints** under `/oidc`. Relying parties, resource servers and
   devices call them with the HTTP shapes that OAuth 2.0 and OpenID Connect
   define: query strings, form-encoded bodies, HTTP Basic client
   authentication, `DPoP` proofs, OAuth error bodies and redirects.
2. **Administration and interaction routes** under `/api/v1/oidc-client` and
   `/api/v1/oidc`. They are ordinary SESAME routes: `POST`, a JSON body that
   the route declares, and a JSON answer.

SESAME is not OpenID certified. The engine's own section on relying parties in
`api/machine/v1/README.md` lists what is implemented and what is not.

## Standard endpoints

| Route | Standard | Engine endpoint (`standards.dispatch`) |
| --- | --- | --- |
| `GET /oidc/openid-configuration` | OpenID Connect Discovery 1.0 | `oidc.discovery` |
| `GET /oidc/jwks` | JWK Set (RFC 7517) | `oidc.jwks` |
| `GET /oidc/authorize` | authorization endpoint (RFC 6749, PKCE RFC 7636) | `oidc.authorization` |
| `POST /oidc/token` | token endpoint: authorization code, refresh token, device code (RFC 8628); `DPoP` (RFC 9449) | `oidc.token` |
| `POST /oidc/introspect` | token introspection (RFC 7662) | `oidc.introspection` |
| `POST /oidc/revoke` | token revocation (RFC 7009) | `oidc.revocation` |
| `GET /oidc/logout` | RP-Initiated Logout 1.0 | `oidc.logout` |

Every standard endpoint is public (`@Public`). Client authentication is part
of each protocol, and the engine performs it: the host never decides whether a
client secret, a code, a refresh token or a proof is good. Discovery publishes
these exact routes under the configured issuer, so a relying party that reads
discovery finds them.

### Why these routes take the raw request

Every other SESAME route binds a typed JSON model. These routes do not: their
wire formats are protocol formats (form-encoded bodies, query strings,
`Authorization` and `DPoP` headers, OAuth error bodies, `303` redirects), not
SESAME models. Each route takes the raw `*http.Request` and returns a
`*http.Response`. This is the one place in the host that does so. The
translation follows the host-adapter contract
([`api/standards/v1`](../../api/standards/v1/README.md),
[RFC 0002](../rfcs/0002-host-adapter-contract-v1.md)) exactly as
`examples/hostserver/standards.go` does:

- The query and form are copied as multimaps, so a duplicated OAuth parameter
  reaches the engine and is refused instead of being silently collapsed.
- A body larger than 128 KiB is refused before the engine runs.
- Only `Authorization` and `DPoP` cross to the engine. Either header sent
  twice is refused.
- When a `DPoP` proof is present, the host reports the public URI it served:
  the scheme from `X-Forwarded-Proto` (which `ty` sets itself and only accepts
  from a proxy listed in `server.proxies`), the `Host` (which `ty` only accepts
  from `localhost`, an IP address or `server.hosts`), and the path. The engine
  refuses a URI outside the issuer's origin.
- The engine's answer is checked before anything is sent: contract version
  `1`, a status from 200 to 599, only the seven contract headers (`allow`,
  `cache-control`, `content-type`, `location`, `pragma`, `www-authenticate`,
  `x-content-type-options`), no CR or LF in a header value, and an
  interaction action only from the authorization endpoint. Anything else
  answers `503 {"error":"server_error"}` with `Cache-Control: no-store`.
- Host refusals use the OAuth shape: `400 {"error":"invalid_request"}` with
  `Cache-Control: no-store` and `Pragma: no-cache`.
- Token, introspection, revocation, logout, authorization and every error
  answer carry `Cache-Control: no-store`; token answers also carry
  `Pragma: no-cache`. These headers come from the engine.
- Redirects are only the engine's: an authorization request with an
  unregistered `redirect_uri` answers `400` with no `Location`, and logout
  returns only to a registered `post_logout_redirect_uri`, matched exactly.
- Error answers contain OAuth error codes only. A wrong client secret answers
  `401 {"error":"invalid_client"}` with `WWW-Authenticate` and never echoes
  the secret.
- When the engine cannot run (another request holds the deployment for the
  whole wait), the route answers `503 {"code":"engine_busy"}` with
  `Retry-After: 1`, like every other route.

A revocation succeeds with an empty body. `ty` refuses an empty answer that has
no `Content-Type`, so the host types an empty body `text/plain;
charset=utf-8`. RFC 7009 tells clients to ignore the body.

### The authorization endpoint and the interaction cookie

A valid authorization request starts an interaction. SESAME owns no login page,
so `GET /oidc/authorize` answers `200` with the public part of the interaction:

```json
{"interaction_id":"int_...","client_id":"cli_...","client_name":"Portal","scopes":["openid"],"expires_at":"..."}
```

and keeps the interaction secret out of the body. The secret is
bearer-equivalent, so it travels only in a cookie:

```text
Set-Cookie: __Secure-sesame_interaction=<interaction_id>:<interaction_secret>; Path=/api/v1/oidc; Max-Age=900; HttpOnly; Secure; SameSite=Lax
```

`HttpOnly` keeps it away from browser JavaScript, `Secure` keeps it off plain
HTTP, the `__Secure-` prefix makes the browser refuse the cookie unless it was
set over HTTPS with `Secure` (no `Domain` is set), and the path sends it only to the interaction routes below. The
interaction and the cookie both last 15 minutes. The browser that started the
interaction then signs in with the `authn` routes and calls
`POST /api/v1/oidc/interaction-complete`; the answer names the redirect URI and
code that the engine validated, and the client application sends the browser
there.

### Discovery at `/.well-known/openid-configuration`

OpenID Connect Discovery requires the document at
`<issuer>/.well-known/openid-configuration`. Tachyon cannot route that path
today: a route segment may only use lowercase letters, digits and hyphens, so
`@RequestRoute("/.well-known")` fails the build with

```text
error[TY2015]: The part '.well-known' of the route path '/.well-known/openid-configuration' may use only lowercase letters, digits and single hyphens.
```

The host therefore serves discovery at `GET /oidc/openid-configuration`.
Operators must rewrite the well-known path in the reverse proxy that
terminates TLS, for example with nginx:

```nginx
location = /.well-known/openid-configuration {
    proxy_pass http://127.0.0.1:8080/oidc/openid-configuration;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

With the issuer `https://id.example`, the well-known URL is
`https://id.example/.well-known/openid-configuration`. The proxy must keep the
`Host` header, list itself in `server.proxies`, and put the public host name in
`server.hosts`, so that `DPoP` proofs are checked against the public URI.

## Administration and interaction routes

Every route is `POST` and answers JSON. A body with a field the route does not
declare is refused with `400` before SESAME runs, so a self-service body cannot
name another principal, session or tenant.

| Route | Operation | Who may call | Bound to the caller |
| --- | --- | --- | --- |
| `POST /api/v1/oidc-client/register` | `oidc_client.register` | an administrator | the body's `tenant_id` must be the caller's tenant |
| `POST /api/v1/oidc-client/get` | `oidc_client.get` | an administrator | the client is loaded, then refused unless it is in the caller's tenant |
| `POST /api/v1/oidc-client/rotate-secret` | `oidc_client.rotate_secret` | an administrator, signed in within 10 minutes (older: `403 {"code":"reauthentication_required"}`) | as `get`; nothing is rotated otherwise |
| `POST /api/v1/oidc-client/disable` | `oidc_client.disable` | an administrator | as `get`; nothing is disabled otherwise |
| `POST /api/v1/oidc/refresh-family-get` | `oidc.refresh_family_get` | an administrator | the family is loaded, then refused unless it is in the caller's tenant |
| `POST /api/v1/oidc/refresh-family-revoke` | `oidc.refresh_family_revoke` | an administrator | as `refresh-family-get`; nothing is revoked otherwise |
| `POST /api/v1/oidc/interaction-get` | `oidc.interaction_get` | any signed-in principal | interaction id and secret from the `__Secure-sesame_interaction` cookie; a wrong or missing secret answers `404 {"code":"interaction_not_found"}` like an unknown interaction; refused unless it is in the caller's tenant |
| `POST /api/v1/oidc/interaction-complete` | `oidc.interaction_complete` | any signed-in principal | interaction id and secret from the cookie; the caller's own session completes it |
| `POST /api/v1/oidc/consent-grant` | `oidc.consent_grant` | any signed-in principal | the caller's own session states the consent; body: `client_id`, `scopes` |
| `POST /api/v1/oidc/consent-get` | `oidc.consent_get` | any signed-in principal | the caller's own principal; body: `client_id` |
| `POST /api/v1/oidc/consent-withdraw` | `oidc.consent_withdraw` | any signed-in principal | the caller's own principal; body: `client_id` |
| `POST /api/v1/oidc/device-lookup` | `oidc.device_lookup` | any signed-in principal | the caller's tenant; body: `user_code` |
| `POST /api/v1/oidc/device-approve` | `oidc.device_approve` | any signed-in principal | the caller's tenant and own session; body: `user_code` |
| `POST /api/v1/oidc/device-deny` | `oidc.device_deny` | any signed-in principal | the caller's tenant; body: `user_code` |
| `POST /api/v1/oidc/pushed-authorize` | `oidc.pushed_authorize` | anyone | none: the engine authenticates the client (`client_id`, `client_secret`) |
| `POST /api/v1/oidc/device-authorize` | `oidc.device_authorize` | anyone | none: the device asks for a code for a registered client |
| `POST /api/v1/oidc/dpop-verify` | `oidc.dpop_verify` | anyone | none: the access token and a fresh proof for it are the credential |

An anonymous caller, or a session that is unknown, expired or revoked, gets
`401` on the signed-in and administrator routes. A signed-in principal that is
not an administrator gets `403` on the administrator routes. A record of
another tenant answers `403 {"code":"tenant_mismatch"}`.

### Client secrets

`oidc_client.register` returns a confidential client's secret, and
`oidc_client.rotate_secret` returns the new one. That answer is the only place
the secret ever appears: `oidc-client/get` and every other route answer without
it, SESAME stores only a one-way verifier, and the host never logs request or
answer bodies. Store the secret when you receive it. Rotation invalidates the
previous secret at once. A public client gets no secret.

### Why each route is guarded this way

**Client and refresh-family administration** changes which applications may
obtain tokens in a tenant, so it needs the `Administrator` role, and each route
checks the tenant of the client or family it acts on before acting. A refresh
family id is never shown to clients; it is recorded in the security-event
ledger, which is where an administrator finds it.

**Interaction, consent and device approval** are statements by the person who
is signed in. The host takes the session, principal and tenant from the
caller's `Sesame-Session`, never from the body, so a caller can complete an
interaction, consent, look up a user code or approve a device only as itself
and only in its own tenant. A user code of another tenant answers
`user_code_not_found`. The engine verifies the session again and refuses one
from another tenant.

**Pushed authorization, device authorization and DPoP verification** are
protocol steps of a client, a device or a resource server, not of a signed-in
person. They are public, and the engine authenticates what each protocol
requires.

## Operations that have no RPC route

These operations are served only by the standard endpoints above, through
`standards.dispatch`. A second JSON route would be a second, unchecked surface
for the same protocol, and the authorization one would hand the interaction
secret to browser JavaScript:

| Operation | Served by |
| --- | --- |
| `oidc.authorize` | `GET /oidc/authorize` |
| `oidc.token` | `POST /oidc/token` |
| `oidc.introspect` | `POST /oidc/introspect` |
| `oidc.revoke` | `POST /oidc/revoke` |
| `oidc.logout` | `GET /oidc/logout` |
| `oidc.discovery` | `GET /oidc/openid-configuration` |
| `standards.dispatch` | every route under `/oidc`; it is never exposed directly, because its envelope carries values only the host may assert (the served `http_uri`, the discovery route paths) |

## Not yet standard-shaped

The host-adapter contract v1 covers the seven endpoints above. RFC 9126 pushed
authorization requests and the RFC 8628 device authorization request are not
part of it, so their routes take SESAME's JSON shapes instead of form-encoded
OAuth requests, and discovery does not advertise them. Serving them at their
standard shapes needs new contract endpoints in the engine (a contract
review), not host code: the host must not parse OAuth parameters or client
authentication itself.

## Throughput and rate limits

Every request starts an engine (see [docs/YON.md](../YON.md)). The token,
introspection and device routes are called by machines and may be polled;
operators must rate-limit `/oidc/*` and `/api/v1/oidc/*` in the reverse proxy.
A polling device that ignores `interval` gets `slow_down` from the engine.
