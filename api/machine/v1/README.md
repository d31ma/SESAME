# SESAME Machine Protocol v1

Start persistent local mode with:

```text
sesame exec --loop [--deployment DIR | --fylo-binary PATH --fylo-root PATH]
```

A deployment directory created by `sesame init` enables verified projection
snapshots and holds the snapshot MAC key outside FYLO documents. The bare
FYLO flags must be provided together and replay the complete ledger. Without
either, the process answers system operations but fails closed on
storage-backed operations with `storage_not_configured`, and
`system.readiness` reports `not_ready`. Structured JSON diagnostics go to
stderr; stdout carries only protocol frames and never key material.

The process reads UTF-8 NDJSON from stdin and writes protocol frames only to
stdout. Diagnostics go to stderr. Each frame is limited to 1 MiB.

The processor uses only the streams supplied by its owning SDK. It never opens
a network listener. In the initial topology, one host application process owns
one SESAME subprocess and one authoritative FYLO root.

## Operations

| Operation | Parameters | Result |
| --- | --- | --- |
| `system.ping` | `{}` | `{"status":"ok"}` |
| `system.version` | `{}` | immutable build metadata, the machine protocol version, and every operation this binary routes |
| `system.readiness` | `{}` | readiness status and optional reason code |
| `system.metrics` | `{}` | uptime, goroutines, heap, storage flag, per-operation request and per-code error counters (excluding the in-flight request) |
| `tenant.bootstrap` | `{"name":...}` | `{"tenant":{...},"created":bool}` |
| `tenant.get` | exactly one of `{"tenant_id":...}` or `{"name":...}` | one tenant |
| `principal.create` | `{"tenant_id":...,"kind":"human"\|"workload","identifier_namespace":...,"identifier_value":...}` | one principal |
| `principal.get` | `{"principal_id":...}` or `{"tenant_id":...,"identifier_namespace":...,"identifier_value":...}` | one principal |
| `principal.suspend` | `{"principal_id":...}` | the suspended principal |
| `role.create` | `{"tenant_id":...,"name":...,"permissions":[{"action":...,"resource":...,"conditions"?:{...}}]}` | one immutable role |
| `grant.create` | `{"tenant_id":...,"role_id":...}` plus exactly one of `principal_id` or `group_id` | one grant |
| `grant.revoke` | `{"grant_id":...}` | `{"revoked":true}` |
| `authorize.decide` | `{"action":...,"resource":...,"context"?,"policy_version"?}` plus either `tenant_id` and `principal_id`, or `session_id` and `session_secret` | one decision |
| `authenticator.set_password` | `{"principal_id":...,"password":...}` | `{"password_set":true}` |
| `authn.begin` | `{"tenant_id":...,"identifier_namespace":...,"identifier_value":...}` | transaction state |
| `authn.verify_password` | `{"transaction_id":...,"password":...}` | transaction state |
| `authenticator.totp_enroll` | `{"principal_id":...,"issuer"?}` | the shared secret and provisioning URI, returned once |
| `authenticator.totp_activate` | `{"principal_id":...,"code":...}` | `{"activated":true}` |
| `authn.verify_totp` | `{"transaction_id":...,"code":...}` | transaction state, assurance `mfa` |
| `authenticator.recovery_codes_issue` | `{"principal_id":...}` | a fresh code set, returned once |
| `authn.verify_recovery_code` | `{"transaction_id":...,"code":...}` | transaction state, assurance `mfa` |
| `authenticator.passkey_register_begin` | `{"principal_id":...}` | challenge, relying party ID, origin, expiry |
| `authenticator.passkey_register_finish` | `{"principal_id":...,"attestation_object":base64,"client_data_json":base64}` | the stored credential |
| `authenticator.passkey_list` | `{"principal_id":...}` | `{"passkeys":[...]}` |
| `authenticator.passkey_remove` | `{"credential_id":...}` | `{"removed":true}` |
| `authn.passkey_options` | `{"transaction_id":...}` | challenge, relying party ID, origin, the principal's credential IDs |
| `authn.verify_passkey` | `{"transaction_id":...,"credential_id":...,"authenticator_data":base64,"client_data_json":base64,"signature":base64}` | transaction state |
| `authn.complete` | `{"transaction_id":...,"lifetime_seconds"?}` | the issued session, including its only copy of the secret |
| `session.verify` | `{"session_id":...,"session_secret":...}` | the session, without its stored digest |
| `session.revoke` | `{"session_id":...,"reason"?}` | `{"revoked":true}` |
| `authorize.decide_batch` | `{"requests":[...],"policy_version"?}` (at most 100) | `{"decisions":[...]}` |
| `group.create` | `{"tenant_id":...,"name":...}` | one group |
| `group.member_add` | `{"group_id":...,"principal_id":...}` | `{"member":true}` |
| `group.member_remove` | `{"group_id":...,"principal_id":...}` | `{"member":false}` |
| `token.jwks` | `{}` | the public signing key set |
| `oidc_client.register` | `{"tenant_id":...,"name":...,"client_type":"confidential"\|"public","redirect_uris":[...],"scopes"?:[...],"audience"?:"first_party"\|"third_party","post_logout_redirect_uris"?:[...]}` | the client and, for a confidential client, its only copy of the secret |
| `oidc_client.get` | `{"client_id":...}` | one client, without secret material |
| `oidc_client.rotate_secret` | `{"client_id":...}` | `{"client_secret":...}`, returned once |
| `oidc_client.disable` | `{"client_id":...,"reason"?}` | `{"disabled":true}` |
| `oidc.authorize` | `{"client_id":...,"redirect_uri":...,"response_type":"code","scopes":[...],"state"?,"nonce"?,"code_challenge":...,"code_challenge_method":"S256"}` | the interaction handle and its only copy of the secret |
| `oidc.interaction_complete` | `{"interaction_id":...,"interaction_secret":...,"session_id":...,"session_secret":...}` | `{"redirect_uri":...,"code":...,"state"?}` |
| `oidc.interaction_get` | `{"interaction_id":...}` | one interaction, without its digests |
| `oidc.token` | `{"grant_type":"authorization_code","code":...,"redirect_uri":...,"client_id":...,"client_secret"?,"code_verifier":...}` or `{"grant_type":"refresh_token","refresh_token":...,"client_id":...,"client_secret"?,"scope"?}` | the issued token set |
| `oidc.dpop_verify` | `{"access_token":...,"dpop_proof":...,"http_method":...,"http_uri":...}` | whether the key-bound token and its proof agree, and the grant behind them |
| `oidc.pushed_authorize` | `{"client_id":...,"client_secret"?,"redirect_uri":...,"response_type":"code","scopes":[...],"state"?,"nonce"?,"code_challenge":...,"code_challenge_method":"S256"}` | a single-use `request_uri` and its lifetime |
| `oidc.refresh_family_revoke` | `{"family_id":...,"reason"?}` | `{"revoked":true}` |
| `oidc.refresh_family_get` | `{"family_id":...}` | one family, with no token material |
| `oidc.device_authorize` | `{"client_id":...,"scopes":[...]}` | the device code, the user code to display, and the poll interval |
| `oidc.device_lookup` | `{"tenant_id":...,"user_code":...}` | the pending request a person is being asked to approve |
| `oidc.device_approve` | `{"tenant_id":...,"user_code":...,"session_id":...,"session_secret":...}` | the approved request |
| `oidc.device_deny` | `{"tenant_id":...,"user_code":...}` | `{"denied":true}` |
| `oidc.discovery` | `{"authorization_endpoint"?,"token_endpoint"?,"jwks_uri"?,"introspection_endpoint"?,"revocation_endpoint"?}` (host route paths) | the provider configuration |
| `oidc.introspect` | `{"token":...,"client_id":...,"client_secret"?}` | `{"active":bool,...}` |
| `oidc.revoke` | `{"token":...,"client_id":...,"client_secret"?}` | `{"acknowledged":true}` |
| `oidc.consent_grant` | `{"session_id":...,"session_secret":...,"client_id":...,"scopes":[...]}` | the standing consent |
| `oidc.consent_withdraw` | `{"principal_id":...,"client_id":...}` | `{"withdrawn":true}` |
| `oidc.consent_get` | `{"principal_id":...,"client_id":...}` | one standing consent |
| `oidc.logout` | `{"id_token_hint":...,"post_logout_redirect_uri"?,"state"?}` | the ended session and where to return |
| `federation.provider_register` | `{"tenant_id":...,"name":...,"issuer":...,"client_id":...,"client_secret"?,"scopes":[...],"subject_claim"?,"email_claim"?,"linking"?}` | the provider and the discovery fetch the host must perform |
| `federation.provider_configure` | `{"tenant_id":...,"provider_id":...,"discovery_document":...,"key_set_document":...}` | the validated provider metadata |
| `federation.provider_disable` | `{"tenant_id":...,"provider_id":...,"reason"?}` | `{"disabled":true}` |
| `federation.provider_get` | `{"tenant_id":...,"provider_id":...}` | one provider, with no client secret |
| `federation.login_start` | `{"tenant_id":...,"provider_id":...,"redirect_uri":...}` | the login handle and the authorization URL to send the browser to |
| `federation.login_exchange` | `{"tenant_id":...,"login_id":...,"state":...,"code":...}` | the token request the host must perform |
| `federation.login_complete` | `{"tenant_id":...,"login_id":...,"id_token":...}` | the issued session and its principal |
| `saml.provider_register` | `{"tenant_id":...,"name":...,"entity_id":...,"sso_url":...,"certificates":[...],"identifier_namespace"?,"linking"?}` | the registered SAML provider |
| `saml.provider_get` | `{"tenant_id":...,"provider_id":...}` | one SAML provider |
| `saml.provider_disable` | `{"tenant_id":...,"provider_id":...,"reason"?}` | `{"disabled":true}` |
| `saml.login_start` | `{"tenant_id":...,"provider_id":...,"consumer_url":...}` | the AuthnRequest to send and where to send it |
| `saml.login_complete` | `{"tenant_id":...,"login_id":...,"assertion":...}` | the issued session and its principal |
| `scim.client_register` | `{"tenant_id":...,"name":...,"identifier_namespace"?,"can_manage_groups"?}` | the provisioning client and its bearer token, returned once |
| `scim.client_rotate_token` | `{"tenant_id":...,"scim_client_id":...}` | a fresh bearer token; the previous one stops working immediately |
| `scim.client_disable` | `{"tenant_id":...,"scim_client_id":...,"reason"?}` | `{"disabled":true}` |
| `scim.user_create` | `{"token":...,"body":...}` | the provisioned user |
| `scim.user_get` | `{"token":...,"resource_id":...}` | one provisioned user |
| `scim.user_list` | `{"token":...,"filter"?,"start_index"?,"count"?}` | a SCIM ListResponse |
| `scim.user_patch` | `{"token":...,"resource_id":...,"body":...}` | the patched user |
| `scim.user_deprovision` | `{"token":...,"resource_id":...}` | `{"deprovisioned":true}` |
| `scim.group_create` | `{"token":...,"body":...}` | the provisioned group |
| `scim.group_get` | `{"token":...,"resource_id":...}` | one group with its members |
| `scim.group_list` | `{"token":...,"filter"?,"start_index"?,"count"?}` | a SCIM ListResponse |
| `scim.group_patch` | `{"token":...,"resource_id":...,"body":...}` | the patched group |
| `scim.group_deprovision` | `{"token":...,"resource_id":...}` | `{"deprovisioned":true}` |
| `admin.bootstrap` | `{"tenant_name":...,"identifier_namespace":...,"identifier_value":...}` | tenant, role, administrator, grant, and whether anything was created |

`tenant.bootstrap` is idempotent per normalized name: repeating it returns the
existing tenant with `created:false` and appends no second security event, so
clients may retry it after a retryable error. `principal.create` registers a
principal and atomically claims its normalized identifier inside the tenant
and namespace; a second claim returns `identifier_conflict`.
`principal.suspend` records a durable, replay-safe deny state and is
idempotent.

Authorization is default deny. Permissions pair action and resource patterns
of lower-case `:`-joined segments where only the final segment may be `*`;
decision requests must name concrete values. A decision carries a random
`decision_id`, a stable `reason_code` (`allow_role_grant`,
`allow_group_grant`, `deny_no_grant`, `deny_missing_context`,
`deny_principal_suspended`, `deny_principal_not_found`,
`deny_tenant_not_found`, `deny_session_invalid`), and the `policy_version` — the ledger sequence of
the latest policy-affecting event. Pinning a non-current `policy_version`
fails closed with `stale_policy_version`; a batch always answers under one
version.

A permission may require context attributes to equal exact values through
`conditions`, and a request supplies them in `context`. Conditions are
equality-only by design: a general condition language needs the ADR and
abuse review the project plan requires, while exact equality is decidable
and side-effect free. A permission matches only when every required
attribute is present with the exact value; unrelated context attributes are
ignored. When a request would otherwise have matched but omitted a required
attribute, the decision reports `deny_missing_context` and names the
attribute in `missing_context_key` — an attribute name, never a value. That
name appears only when supplying it would change the outcome: if any
supplied attribute holds the wrong value the decision is a plain
`deny_no_grant`, because naming an absent attribute would be false advice.

Authentication is a persisted state machine the engine alone advances. A
client carries the `transaction_id` and renders prompts; it cannot choose the
next state. `authn.begin` succeeds whether or not the identifier resolves and
a suspended principal is treated exactly like an absent one, so neither the
response nor the hashing cost reveals which identifiers exist — an unresolved
transaction is verified against a decoy verifier at the same Argon2id cost.
Attempts are bounded (5) and a transaction expires (10 minutes); both then
return `transaction_closed`. A wrong secret and an unknown session share
`session_not_found` for the same reason.

TOTP follows RFC 6238 with HMAC-SHA1, six digits, and a thirty-second step,
so ordinary authenticator apps interoperate. Enrollment is two steps:
`authenticator.totp_enroll` returns the secret and provisioning URI exactly
once, and the factor stays unusable until `authenticator.totp_activate`
proves a code, so a mis-scanned enrollment cannot leave anyone holding a
factor they cannot produce. Codes are accepted one step either side of now.

A code is spent when it succeeds: its time-step counter is recorded durably,
and any code at or below that counter is refused even while still inside its
own validity window, so an observed code cannot be replayed. The refusal
survives restart and replay. `authn.verify_totp` requires a first factor to
have succeeded already, because a one-time code proves possession of a
device rather than of the account.

The shared secret must be read back to compute the expected code, so unlike a
password it is sealed with AES-256-GCM under a deployment key rather than
hashed. Enrollment therefore requires a deployment and returns
`secrets_not_configured` without one.

Recovery codes are the way back in when the second-factor device is gone.
`authenticator.recovery_codes_issue` returns ten single-use codes once and
retires any previous set, so a leaked set can be replaced by reissuing. A
code is spent durably when used and cannot be used twice, even after a
restart. Like TOTP, `authn.verify_recovery_code` requires a first factor: a
recovery code is a backup for the second step, not a way to skip the first.

### Relying parties

A registered client is the trust anchor of every browser-facing flow. Its
redirect URIs are matched by exact string equality: wildcards, prefixes, and
path patterns are rejected at registration, so no request-time comparison can
be talked into delivering an authorization response somewhere else. A redirect
URI must be an absolute, fragment-free `https` URI, or `http` on a loopback
address (RFC 8252 section 7.3).

`confidential` clients receive a generated secret, returned once and stored
only as an Argon2id verifier. `public` clients receive none — a secret shipped
inside a distributed app is not a secret — and prove possession of the flow
with PKCE instead. `oidc_client.rotate_secret` invalidates the previous secret
at the same moment it issues the new one, and `oidc_client.disable` is durable
and idempotent.

There is no grant-type parameter. SESAME issues authorization codes and, when
`offline_access` is registered, refresh tokens; the implicit and
resource-owner-password grants are not modelled, so no configuration turns
them on.

### The external interaction contract

SESAME owns no listener and renders no page, so a browser-facing flow runs as
an interaction the host drives:

1. The host receives an authorization request and calls `oidc.authorize`.
   Everything that could be wrong with the request is found here, before a
   login page exists to be phished through: the client must be registered and
   enabled, the redirect URI must match its registration exactly, the scopes
   must be registered, `response_type` must be `code`, and PKCE must be
   present with `S256`.
2. The engine returns an interaction handle and a one-time secret. The handle
   may be logged; the secret is bearer-equivalent, stored only as a digest,
   and is what authorizes step 4.
3. The host authenticates the user with the ordinary `authn` operations,
   however it likes — including MFA and step-up — and ends up with a session.
4. The host calls `oidc.interaction_complete` with the interaction secret and
   the session. The engine verifies the session itself rather than taking the
   host's word, refuses one from another tenant, and returns the code with
   the redirect URI *it* validated in step 1 and the client's original
   `state`.
5. The client redeems the code at `oidc.token` on the back channel.

An interaction lives 15 minutes; a code lives 60 seconds and is single-use.
Redeeming re-checks every binding made in step 1 — client, redirect URI, and
PKCE verifier — and refuses if the session has been revoked or the principal
suspended in the meantime. Every one of those failures returns the same
`invalid_grant` code, because telling them apart tells an attacker which half
of a guess was right.

Access and ID tokens are ES256 JWTs signed with the deployment key. The ID
token carries the request's `nonce`, and `acr` reports how the principal
proved identity, so a relying party can require more than a password without
asking SESAME again.

### Refresh tokens

A client registered for `offline_access` that requests it receives a refresh
token alongside the token set. Every use rotates: the presented token is spent
and a successor issued in the same family, and the response's refresh token
replaces the one that was sent.

Rotation is what makes theft detectable. A legitimate client always holds the
newest token, so a spent one arriving means two parties hold tokens from one
family and one of them is a thief. SESAME cannot tell which, so
`oidc.refresh_family_revoke` fires against the whole family — including the
successor the legitimate client is holding. That client re-authenticates,
which is the right cost when the alternative is leaving the thief with a live
grant. The spent state is durable, so reuse detection survives replay,
snapshot restore, and restart.

`scope` on a refresh may narrow the granted set and can never widen it.
Dropping `offline_access` ends the family's ability to refresh, which is the
honest consequence of asking for less.

A refresh token is bound to its client and to the session that authorized it.
Revoking that session, suspending the principal, or disabling the client ends
the grant. Session *expiry* does not: `offline_access` exists for when the
user is away, so only a deliberate revocation counts. Absolute bounds still
apply — one token lives 30 days, and no amount of rotation extends a family
past 90.

An ID token minted from a refresh carries no `nonce`: it attests to no new
authentication event (OpenID Connect Core section 12.2).

### Discovery

`oidc.discovery` returns the OpenID provider configuration. Its capability
lists are not a hand-written document: they are the same slices the request
validators read, so an advertised response type, grant, PKCE method, or
signing algorithm is by construction one the engine accepts, and one that is
not advertised is one it refuses. A hand-written metadata document is a
promise nothing enforces; this one cannot drift.

The host names its own route paths, because the host owns every route. The
engine composes them under the configured issuer and refuses any that would
leave that origin — an off-origin `token_endpoint` in a discovery document is
how a relying party gets walked onto an attacker's token endpoint, so it is
refused rather than published. Omitted paths take conventional defaults.

### Introspection and revocation

`oidc.introspect` answers the one thing a self-contained access token cannot:
whether the authentication behind it still stands. A verifying signature is
not a standing grant — the session may have been revoked or the principal
suspended since it was minted, and this is where that shows up. An inactive
answer is `{"active":false}` and nothing else (RFC 7662 section 2.2).

The calling client must authenticate and may only introspect tokens issued to
itself. A resource server that is a separate client cannot yet introspect on a
token's behalf; that needs an audience/resource registration design rather
than a looser rule.

`oidc.revoke` ends a refresh token's whole family. An access token is a signed
JWT SESAME cannot recall — the honest way to end one early is to revoke the
refresh family or the session behind it. Either way the response is the same
`{"acknowledged":true}`, because RFC 7009 section 2.2 requires success for an
unknown token too; an endpoint that distinguished them would confirm token
guesses.

**SESAME is not OpenID certified.** The engine implements discovery, JWKS,
authorization code with PKCE, token, introspection, revocation, and
RP-initiated logout, and `test/adversarial` exercises them against a real
binary — but that suite tests SESAME against SESAME's own reading of the
specifications, which is the thing an independent conformance profile exists to
check. Certification requires running the OpenID Foundation suite against a
deployed host, and that run has not happened.

Not implemented, and not claimed: back-channel and front-channel logout
notification to other clients, WebAuthn attestation statement verification, and
COSE algorithms other than ES256.

### Consent

Registering a client declares which scopes it *may* request. That is an
administrator's decision, and for a `first_party` client — where the
administrator and the organization running the account are the same party —
it is the only decision needed.

A `third_party` client is different: "this app may request your email" was
decided by someone who is not the person whose email it is. Such a client
cannot obtain an authorization code until `oidc.consent_grant` has recorded
that this principal agreed to these scopes for this client.
`oidc.interaction_complete` returns `consent_required` instead, which is not a
failure — the interaction stays live, and the host is expected to show a
consent screen and come back to the same interaction.

An omitted `audience` is treated as third party. A default that failed open
here would silently exempt exactly the clients most likely to need asking.

The gate compares the consent against the scopes **requested**, not the scopes
registered, so agreeing to `openid` does not authorize a later request that
also wants `profile`. Re-granting merges rather than replaces. A principal can
never consent to more than the client is registered for: consent narrows an
administrator's decision, it never widens it.

Consent is a statement by a specific authenticated person, so
`oidc.consent_grant` takes a session and verifies it rather than accepting a
principal ID from the caller. `oidc.consent_withdraw` is durable and
idempotent, and it also revokes every refresh family that client holds for
that principal — a consent the user has taken back while the client keeps
minting tokens would be a withdrawal in name only.

### Logout

`oidc.logout` implements OpenID Connect RP-Initiated Logout. The
`id_token_hint` is **required**: SESAME is headless and holds no browser
session of its own, so without it there is nothing identifying which session to
end, and taking the session from anything the caller supplied directly would
let one party log another out at will.

Revoking that session is the whole mechanism. Every refresh grant checks that
its session is unrevoked, so one durable revocation ends the browser session
and every refresh token resting on it together — rather than leaving the client
quietly able to mint more.

The audience is read *from* the hint rather than supplied alongside it, so a
caller cannot present one client's token while claiming to be another, and a
hint whose subject does not own the session it names ends nothing. A
`post_logout_redirect_uri` must be registered on that client and is matched
exactly: logout is a redirect endpoint like any other, and a loose match here
is an open redirect with a friendly name.

An **expired** hint is accepted. It authorizes nothing — it names a session to
end — and a user reaching for "sign out" is often doing so precisely because
their tokens have aged. The cost is bounded: someone holding an old ID token
can end a session, which only ever reduces access and is idempotent. Signature,
issuer, audience, and key identifier are all still enforced. Logout is
idempotent, and a second call reports `session_revoked:false` rather than an
error.

### Passkeys

A passkey is the only factor SESAME supports that is phishing-resistant by
construction. The authenticator signs over the origin the browser is actually
talking to, so an assertion collected by a convincing replica of the login page
names the replica and is refused.

Scope is deliberately narrow and stated rather than implied:

- **attestation format `none` only.** Any other format is refused rather than
  accepted without verifying its statement — an unverified attestation is a
  claim about hardware that nothing checked, which is worse than not asking.
  Verifying the others means shipping and rotating vendor root certificates,
  and platform guidance for passkeys is not to require attestation.
- **COSE ES256 only,** matching the token signing boundary. Nothing is
  negotiated, so nothing can be confused.

Challenges are engine-issued. A registration challenge lives five minutes, is
spent on the first attempt whether it succeeds or fails — so a rejected
attestation cannot be retried with different bytes against a live nonce — and
is held only in memory: losing it on restart costs one retry, while a durable
one would put an event in the ledger for every abandoned registration. An
authentication challenge lives on the transaction, which is already durable, so
an assertion belongs to exactly one transaction and cannot be replayed into
another.

`authn.begin` issues a passkey challenge for every transaction, whether or not
the principal has one registered. Issuing it only for principals that do would
tell an attacker which accounts have passkeys.

Unlike TOTP and recovery codes, a passkey needs no prior factor: it proves
possession of a key that never left the authenticator, and when the
authenticator also verified the user it establishes `mfa` assurance on its own.
Without user verification it is possession alone and yields `password`-level
assurance. Requiring a password first would reintroduce the thing being
replaced.

A sign counter that fails to advance is treated as a cloned authenticator and
refused; the counter is durable, so that survives a restart. An authenticator
that reports a constant zero is the documented counter-not-supported case, not
a clone. `authenticator.passkey_remove` is the lost-device response.

Every way a passkey can be wrong returns one `passkey_rejected` code. Which
check failed is diagnostic detail an attacker does not need.

### Signing keys

`token.jwks` returns the public half of the deployment signing key in JWKS
form, for the host to serve at its own `/.well-known/jwks.json`. The private
key lives in the deployment key directory and never enters a FYLO document, so
a stolen data root does not confer the ability to mint tokens; without a
deployment the operation returns `signing_not_configured` rather than an empty
key set, because an empty set reads as "this issuer signs nothing".

SESAME signs with ES256 and verifies with ES256 only. A token header's `alg`
and `kid` must match the configured key exactly; nothing is negotiated, so
`alg: none` and symmetric-algorithm confusion have nothing to act on.

### Step-up

A decision may carry `session_id` and `session_secret` instead of naming a
tenant and principal. The engine then verifies the session and derives the
principal, the tenant, and a `session.assurance` context attribute from it,
so a permission can require a proven second factor:

```json
{"action":"billing:write","resource":"*","conditions":{"session.assurance":"mfa"}}
```

Attributes under the reserved `session.` prefix are derived, never supplied:
a request that tries to set one is rejected with `invalid_request` rather
than silently ignored, so a policy author can trust what the prefix means. A
request with no session simply lacks the attribute and is denied with
`deny_missing_context` naming `session.assurance`, which tells the host to
step up and retry. An unusable session — unknown, wrong secret, expired,
revoked, suspended principal, or a mismatched tenant or principal — denies
with `deny_session_invalid` rather than answering from a session the caller
does not hold.

`authn.complete` returns `session_secret` once. It is stored only as a
SHA-256 digest and cannot be recovered; `session.verify` never returns the
digest. Passwords are never echoed by any operation.

`api/machine/v1/decisions.golden.json` is the deterministic golden decision
corpus. The engine test and the Go, Node, and Python SDK suites all build
that fixture and assert its outcomes, so these semantics have exactly one
definition.

A grant names exactly one subject: a principal or a group. Group grants
apply to present and future members, so `group.member_add` and
`group.member_remove` change decisions immediately and durably; a decision
allowed through membership reports `allow_group_grant`.

`admin.bootstrap` converges a deployment to one administrator — tenant,
administrator role, administrator principal, and grant — creating only what
is missing, so an interrupted bootstrap can be retried without producing a
second administrator. It establishes no credential: give the administrator
one with `authenticator.set_password`.

Storage-backed operations return `storage_not_configured` when the process
runs without a FYLO root; `tenant_not_found`, `principal_not_found`,
`role_not_found`, `grant_not_found`, `group_not_found`, or
`group_member_not_found` for missing records; `role_exists`, `grant_exists`,
`group_exists`, `group_member_exists`, or `identifier_conflict` for
uniqueness conflicts; and `invalid_request` for malformed parameters;
`transaction_not_found` or `transaction_closed` for authentication
transactions; `session_not_found` or `session_inactive` for sessions; and
`totp_not_enrolled`, `totp_already_active`, `totp_invalid_code`, or
`secrets_not_configured` for TOTP; `client_not_found`, `client_exists`, or
`client_disabled` for relying parties; `interaction_not_found`,
`interaction_closed`, `invalid_redirect_uri`, `scope_not_allowed`, or the
deliberately undifferentiated `invalid_grant` for the code and refresh grants;
`refresh_family_not_found` for family administration; `passkey_not_found`,
`passkey_exists`, `passkey_challenge_expired`, `passkey_rejected`, or
`relying_party_not_configured` for passkeys; `invalid_logout_hint` or
`invalid_post_logout_redirect_uri` for logout; `consent_required` when
a third-party client needs the user asked, and `consent_not_found` for consent
administration; `invalid_request` for a
discovery endpoint outside the issuer origin;
and `signing_not_configured` or `issuer_not_configured` for token operations
without a deployment signing key or issuer.


## Inbound OIDC federation

SESAME acts as a relying party to an external OpenID Provider, and performs no
network I/O of its own. `net/http` is absent from the engine's dependency
graph and a test fails the build if it appears, so the four requests
federation needs are made by the host:

1. `federation.provider_register` returns the discovery URL to fetch;
2. `federation.provider_configure` takes that document plus the key set, and
   validates both;
3. `federation.login_start` returns the authorization URL for the browser;
4. `federation.login_exchange` returns the token request to perform;
5. `federation.login_complete` takes the resulting ID token and issues a
   session.

Every URL the engine emits is derived from the registered issuer, never from a
caller, so there is no caller-controlled address for an attacker to aim the
host at. Every document the host returns is parsed and validated inside the
engine under bounded sizes: the host is a transport, never a validator.

The registered issuer is the trust anchor. A discovery document must declare
exactly that issuer, and every endpoint it names must sit on that issuer's
origin over https — otherwise a compromised provider could move the token
exchange, which carries SESAME's client secret, to a server of its choosing.

ID tokens are verified against a closed algorithm allowlist — RS256, RS384,
RS512, ES256, ES384, ES512 — with the key pinned by `kid`, a 2048-bit floor on
RSA moduli, and on-curve checks for EC keys. `none` and every MAC algorithm are
absent. SESAME continues to sign only with ES256; verifying another party's
choices is a separate question from making its own.

Every rejected assertion returns one code, `assertion_rejected`, whatever the
cause. A caller who can tell "wrong nonce" from "unknown key" from "bad
signature" learns the shape of the flow; the specific reason goes to the audit
ledger instead.

A federated session carries `federated` assurance, which is deliberately
distinct from `password`. SESAME did not witness the credential, so a
federated session does not satisfy a step-up requirement that a locally proven
factor would.

**The host's obligations.** SESAME cannot enforce these from the far side of a
pipe, so they are stated rather than implied. The host must resolve and connect
only to public addresses, refuse redirects into private ranges, bound response
size and time, and keep TLS verification on. `federation.login_exchange`
returns the provider's client secret in the form body, because the host makes
that call; treat that response as credential material.

## Compatibility

`system.version` answers the two questions a client has before it starts a flow
it cannot finish: *may I talk to you*, and *can you do what I need*. It returns
`protocol_version` alongside the build identity, and `operations` — every
operation this binary routes, sorted.

Every SDK performs that handshake at startup and refuses an engine speaking a
different protocol version, rather than discovering the mismatch partway
through a login. The error names both sides, because the fix is always to
change one of them. Each SDK also exposes `requireOperations`, for an
application to assert at startup that the operations it depends on exist; a
newer client against an older engine is otherwise perfectly usable as long as
it never calls what is missing.

The reported list is the same set as the dispatch table and
`operations.json`; `test/contract` asserts all three against each other, so a
client that trusts what the engine reports is trusting something checked.

- `protocol_version` is required and currently must equal `"1"`.
- Unknown and duplicate object fields are rejected.
- Every request receives at most one response with the same `request_id`.
- Human-readable error messages are not a parsing contract.
- Clients branch on stable `error.code` and `error.retryable` values.
- The process continues after a validly framed request error.
- An oversized frame terminates the loop after an error response because frame
  boundaries can no longer be trusted.

`operations.json` beside this file is the machine-readable twin of the table
above: the canonical operation set, plus the operations each SDK shim does not
yet expose as a typed method. It is asserted three ways by `test/contract` —
against the engine's own dispatch table (parsed from the processor, so the
manifest cannot claim an operation the engine does not route), against this
document (so no operation ships undocumented), and against each SDK's source
(so a gap cannot be opened or closed without recording it). A gap means no
typed method, not no access: every SDK reaches every operation through its
generic request escape hatch.

See `api/schema/machine-v1.schema.json` and
`docs/rfcs/0001-machine-protocol-v1.md`.
