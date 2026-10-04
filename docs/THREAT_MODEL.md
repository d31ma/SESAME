# SESAME Initial Threat Model

## Scope

This document covers the planned single-owner SESAME v1 engine, its host
application, FYLO child process and local data root, operator CLI, local machine
interface, the Yon host (`app/server/`), the Go package and framework adapters,
external interaction clients,
protocol endpoints exposed by the host, connectors, key-management boundary,
release artifacts, and audit export.

It is an initial model. Every vertical slice must update it with concrete data
flows, trust boundaries, and mitigations.

## Assets

- passwords and password verifiers;
- passkey public-key credentials and metadata;
- TOTP seeds, recovery material, and enrollment challenges;
- sessions, authorization codes, refresh tokens, and signing keys;
- principal attributes and tenant configuration;
- authorization policies, grants, and decision inputs;
- audit evidence and recovery data;
- connector credentials and remote assertions.

## Trust Boundaries

1. Untrusted protocol or API client to the host application's HTTP edge.
2. Host framework adapter to the local SESAME machine process.
3. Operator CLI, `ty handler invoke` and the Go package to privileged
   administration commands.
4. External interaction client to persisted authentication transactions.
5. Local Go package (in the Yon host or a Go application) to the SESAME NDJSON
   machine process.
6. SESAME command coordinator to the FYLO machine process.
7. SESAME/FYLO processes to the local filesystem.
8. SESAME to the external key-management or sealed-file boundary.
9. SESAME to email, federation, provisioning, webhook, and audit destinations.
10. Operator and host administrator access to the deployment.
11. Release archives, installers, package registries, and update channels.
12. Reverse proxy to `ty`, and `ty`'s route guard and identity check to the Yon
    controllers (see "The Yon Host" below).

## Primary Threats and Planned Controls

| Threat | Planned controls |
| --- | --- |
| Credential stuffing and password spraying | passkey-first UX, rate limits by multiple dimensions, breached-password checks where deployable, risk signals, privacy-preserving errors |
| Account enumeration | uniform public responses, bounded timing differences, audited privileged lookup |
| Session fixation or theft | post-auth rotation, secure host-only cookies, CSRF defense, device/session view, short lifetimes, revocation epochs |
| OAuth code or token replay | PKCE, single-use serialized redemption, token-family rotation, reuse detection, exact redirect matching |
| Access-token theft in transit or at rest | DPoP (RFC 9449) key binding on request: `cnf.jkt` in the token, per-request proof bound to method, URI, and token hash, durable `jti` replay store, binding preserved across refresh rotation |
| Authorization-request tampering in the user agent | PAR (RFC 9126): the request is pushed on an authenticated back channel and the browser carries only a single-use, client-bound, ninety-second reference; loose parameters beside a reference are refused rather than merged |
| Tenant escape | explicit tenant key everywhere, repository-level scoping, adversarial cross-tenant tests, deny on missing scope |
| Policy bypass | default deny, typed inputs, immutable policy versions, deterministic precedence, enforcement-point tests |
| Admin takeover | phishing-resistant MFA, step-up, least privilege, separate admin session, emergency lockdown, audit export |
| SSRF through connectors | deny-by-default egress broker, scheme/host/port allowlists, DNS and redirect revalidation, private-range denial, response limits |
| Malicious federation metadata or keys | pinned issuers, algorithm allowlists, bounded fetches and caches, key-selection constraints, safe XML/JSON parsing |
| FYLO data-root tampering | local permissions, startup integrity verification, hash-chained events, external signed audit anchors, recovery fail-closed |
| Partial storage commit | one authoritative event per command, FYLO durable append, acknowledgement only after commit, crash-injection tests |
| Duplicate identifier or token use | one writer, serialized conflict keys, idempotency records, property and concurrency tests |
| Secret disclosure in storage | application envelope encryption, external KEK/pepper, no plaintext audit, crypto-erasure |
| Secret disclosure in logs | structured allowlisted fields, redaction tests, no request-body logging on sensitive endpoints |
| Supply-chain compromise | minimal dependencies, locked modules, SBOM, provenance, signed releases, pinned CI actions |
| Shim divergence or confused versioning | canonical schemas, protocol negotiation, typed stable errors, compatibility suites against real release binaries |
| Local machine-protocol injection | one JSON object per line, strict size/schema validation, no shell interpolation, child lifecycle ownership, stderr separation |
| Malicious interaction client | one-time scoped transaction handles, exact continuation binding, CSRF protection, origin policy, no direct state mutation, complete audit |
| Package substitution | checksums, signatures, provenance, pinned FYLO digest, archive manifest, verified install/update path |
| Denial of service | request/body limits, bounded parsers, admission control, queue budgets, expensive-operation isolation |
| Misattributed audit actor (a host names the wrong principal) | the optional `actor` is shape-checked, cross-checked against a live session of that principal and tenant, may only be recorded on its own tenant's events, and never grants access; an absent actor records `operator:machine` |
| Cross-tenant state probing through idempotent writes | attributed writes check the target's tenant before any state-dependent answer (a no-op or a refusal answers `actor_tenant_mismatch` too) |
| Clock manipulation | explicit skew policy, monotonic durations in-process, monitored UTC source, no reliance on TTID as a security clock |

## Theft of the Data Root

The question this section answers: an attacker copies the FYLO data root and
the snapshots — a stolen disk, a leaked backup, a misconfigured volume — but
does **not** get `<deployment>/keys/`. What can they use?

### Credentials: nothing they can present

Every credential is stored in a form that cannot be replayed, and the forms
differ because the requirements do.

| Credential | Stored as | Why that form |
| --- | --- | --- |
| Password | Argon2id PHC string, per-password 16-byte salt | One-way. Never needs to be read back, only compared. |
| Session secret | SHA-256 digest | Generated from the system CSPRNG, so the digest is not brute-forceable the way a human password would be. |
| Recovery code | SHA-256 digest | Same: high entropy, single use, spent durably. |
| Authorization code, interaction secret, refresh token | SHA-256 digest | Short-lived and single-use on top of that. |
| OIDC client secret | Argon2id verifier | A client secret is compared, never retrieved. |
| TOTP shared secret, federation client secret | AES-256-GCM sealed | These *must* be readable to compute an expected code or authenticate outbound, so hashing is not available. The sealing key lives in the key directory, outside every FYLO document. |
| Signing key | Not in FYLO at all | Only its public half is ever published, through JWKS. |

`test/adversarial/stolen_store_test.go` plants a distinctive value for each of
those, exercises the flows that persist them, then reads every byte under the
deployment looking for them. It runs on every push. That test is what turns
the table above from an argument into a check.

**The bound on this claim** is the key directory. Everything above assumes the
attacker did not also take `keys/`. If they did, sealed secrets — TOTP shared
secrets and federation client secrets — are recoverable, and they can mint
tokens with the signing key. Passwords, sessions, recovery codes, and client
secrets remain one-way even then. Store the key directory somewhere the data
root's backups do not reach; that separation is the whole design.

### Personal data: fully exposed

This is the honest other half, and it is a real weakness rather than an
oversight to be explained away.

Identifiers (email addresses, logins), tenant and group names, role and
permission definitions, and the entire audit trail are stored **in the clear**.
The engine has to query, project, and enforce uniqueness on them. A thief with
the data root learns:

- who has an account, and under which tenant;
- what groups and roles they hold;
- when they authenticated, from which actor, and what was decided about them;
- the shape of the organisation.

`TestStolenDataRootStillExposesWhoIsThere` asserts this on purpose, so the
exposure is stated by the suite rather than discovered by a reader. On a real
FYLO runtime it is worse than a single copy: version-controlled objects retain
history, so an identifier observed once appeared in ninety files in a
development store.

FYLO offers an `$encrypted` field facility that SESAME has **deliberately not
adopted**. It would add a third deployment key whose loss makes every affected
document unreadable, and it needs a rotation and re-encryption design first.
Until that design exists, encryption at rest for personal data is not
implemented and is not claimed.

### What this means operationally

- Treat the data root as containing personal data, not credentials. Back it up
  with the same care you would give a user table.
- Keep `keys/` out of those backups.
- Theft is not authentication: revocation, suspension, and disablement are
  durable, so a stolen store gives no live session.
- A stolen store is a disclosure incident, not an account-takeover incident —
  unless the key directory went with it.

### A stolen access token

DPoP changes this answer, and only for clients that use it. A bearer token is
whoever holds it; every layer between client and resource — a proxy, an access
log, a browser extension, a leaked backup — is somewhere it can be picked up
and replayed, and nothing about the token objects.

A DPoP-bound token is different. It carries the thumbprint of a key the client
holds, and every request has to arrive with a fresh proof signed by that key
and bound to the method, the URI, and the token itself. An attacker who has the
token in full, knows the resource, and can mint syntactically perfect proofs
with a key of their own still gets nothing: `test/adversarial/dpop_test.go`
runs exactly that attacker against a real binary. A captured *proof* buys one
replay attempt, which the durable `jti` store refuses, and it is useless at any
other endpoint.

Three limits are worth stating plainly.

- **The engine does not see the HTTP request.** SESAME opens no listener, so
  `htm` and `htu` are checked against what the host reports. A host that
  reports the wrong URI defeats the binding as surely as one that skipped the
  check. What the engine guarantees alone is that the reported URI is inside
  its own issuer origin.
- **DPoP is per request, not per client.** A client that presents no proof gets
  an ordinary bearer token, deliberately — there is no per-client "DPoP
  required" switch yet.
- **Key theft is not covered.** DPoP protects a token separated from its key.
  A client whose private key is taken is compromised, and the answer there is
  revocation, which remains durable and outranks key possession.

## The Yon Host

`ty` serves SESAME over HTTP from this repository (ADR 0007). It owns the
listener and runs one engine per request. These rows record its specific
threats, the controls in place and what remains.

| Threat | Controls | Residual risk |
| --- | --- | --- |
| Yon host boundary: a request reaches a controller it should not, or acts in another tenant | `ty`'s route guard (`@Public`, `@SignedIn`, `@Allow(Administrator)`) backed by `SesameIdentityProvider` (`session.verify`, then `authorize.decide` of `sesame:administer` on `sesame:tenant`); every administrative call decides the role again inside `TenantCallService` and checks the record's or body's tenant against the session's before the engine runs; the verified caller is the engine's `actor`, so the engine refuses writes into another tenant; `ty` refuses undeclared body fields; `test/contract` pins every route's guard in `operations.json` | `ty` itself is outside SESAME's tests except through `ty serve` checks; a foreign id answers `403` while an unknown one answers `404`, which tells an administrator that some other tenant holds that id (ids are not secrets) |
| Wildcard roles confer tenant administration | the administrator check asks for the reserved `sesame:administer` on `sesame:tenant` | any role whose patterns match it (`*` on `*`, `sesame:*`) silently makes its holders HTTP tenant administrators; operators must treat such roles as administrator roles. An engine-side reservation of the `sesame:` namespace is future work |
| Unauthenticated denial of service of the single engine | every request starts one engine and only one may own the deployment, so requests are serialized with a bounded wait and then `503 engine_busy`; the busy answer is fail-closed (on signed-in routes the identity check fails with `500`, never an anonymous identity) | neither SESAME nor `ty` limits request rates: one anonymous client can keep every other caller waiting and refused. A TLS-terminating reverse proxy with per-IP limits on `authn/*`, `session/verify`, `/oidc/*`, `oidc/pushed-authorize`, `oidc/device-authorize`, `oidc/dpop-verify`, `federation/login-*`, `saml/login-*`, `scim/*` and `system/*` is required (docs/YON.md); `ty` must never be exposed directly |
| Stolen session used to change credentials or privileges | self-service authenticator changes and administrator credential and privilege changes need a session issued in the last 10 minutes (`403 reauthentication_required`); sessions are revocable and expire | recent sign-in is not proof of the current credential: a session secret stolen within its first 10 minutes can change the password, add a passkey, or (for an administrator) grant roles and reset other principals' passwords. No route asks for the current password, because the engine has no reauthentication primitive for `authenticator.*`; closing this needs one |
| Command-line bypass of the route guard; operator trust | `ty handler invoke` skips the guard, but signed-in routes still verify the `Sesame-Session` header and administrative calls decide the role again (`403 administrator_required`); tenant and recent sign-in checks apply as over HTTP; the `sesame` CLI reads secrets from environment variables | anyone who can run `ty handler invoke` or the `sesame` CLI against the deployment is an operator: the `sesame` CLI and the bootstrap commands act as `operator:cli` with full deployment access, by design. `ty handler invoke` puts session secrets on the command line (visible to other local users) and echoes a malformed `--header` value, so it is recommended only on single-user hosts |
| Redirect of a federated or SAML login to an attacker | `federation/login-start` and `saml/login-start` accept only a `redirect_uri` or `consumer_url` listed exactly in the host settings `sesame.federationredirecturis` and `sesame.samlconsumerurls` (absolute `https`, no fragment; empty by default, so both refuse until configured with `400 redirect_not_allowed`) | the allowlist is deployment-wide in the host, not per provider in the engine; the engine still stores whatever URL the host passes. An engine-side per-provider allowlist (needs an ADR and a stored-data change) is future work |

## Explicit v1 Limitations

- The authoritative data plane is single-node and single-writer.
- One host application process owns one SESAME subprocess and authoritative
  FYLO root. Multiple replicas or applications cannot share that root.
- SESAME does not open a network listener. TLS, routing, rate limits, request
  limits, and middleware placement are host-application responsibilities,
  verified by framework-adapter contract tests. The Yon host (`ty`) adds no
  rate limits of its own; a reverse proxy provides them.
- The Yon host starts one engine per request and serializes requests on the
  deployment: a developer-preview throughput of a few requests per second.
- S3 is backup, not synchronous replication or failover.
- A privileged host administrator can modify local files and bypass local WORM
  permissions; external audit anchoring provides detection, not prevention.
- Offline JWT validation cannot provide immediate global revocation. SESAME will
  use short access-token lifetimes and offer introspection or opaque-token modes
  for stronger revocation requirements.
- DPoP proof validation depends on the host reporting the HTTP method and URI
  it actually served. The engine bounds this — a reported URI outside the
  issuer origin is refused — but cannot verify it. `use_dpop_nonce` is not
  implemented, so the proof window is the client's clock plus skew rather than
  a server-supplied challenge.
- Availability depends on the local filesystem and FYLO recovery. Network or
  cloud-synchronized filesystems are unsupported data roots.
- SESAME ships no user interface. Browser-facing OIDC is not a turnkey
  deployment until an approved external interaction client is configured.
- Windows x64 may be built and tested as a preview, but production support is
  blocked until FYLO provides backup/restore parity and SESAME passes native
  recovery gates there.

## Security Release Gates

- Threat model and abuse cases reviewed for every public flow.
- OAuth/OIDC conformance and negative tests pass before support is claimed.
- Fuzzing covers protocol parsers, redirect handling, token parsing, policy
  inputs, and connector URL validation.
- Cross-tenant test corpus reports zero unauthorized reads or writes.
- Logs and traces pass automated secret-canary tests.
- Backup restoration reproduces expected identity and policy decisions.
- Every supported OS/architecture passes native crash, recovery, upgrade,
  packaging, Go package, and Yon host interoperability tests.
- Every published Go package and Yon host passes the shared contract corpus
  against the minimum and maximum compatible SESAME versions.
- A third-party security review is complete before v1.0.
- The project publishes a security policy, supported-version window, and private
  disclosure channel before accepting production users.
