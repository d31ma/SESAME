# Changelog

All notable changes to SESAME will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases will use Semantic Versioning once the first public version is
tagged.

## [Unreleased]

### Added

- Inbound SAML 2.0 vertical slice: an in-tree exclusive XML canonicalizer over
  `encoding/xml`'s raw token stream, signature and digest verification against
  a closed RSA/ECDSA SHA-256/384/512 allowlist, and an element locator that
  defeats XML Signature Wrapping by refusing every ambiguous document rather
  than choosing between readings. `AuthnRequest` construction and the
  HTTP-Redirect binding are performed by the engine so the host never
  implements a protocol detail. Sessions are issued at `federated` assurance;
  assertions are single use, and the spent-assertion claim replays from both a
  snapshot and the full ledger so a restart cannot make a captured assertion
  replayable again. Adds `saml.*` machine operations, a `sesame saml` CLI
  family, typed methods in all ten SDKs, an adversarial suite driven through
  the compiled binary, real-FYLO restart evidence, and
  [docs/SAML.md](docs/SAML.md). The canonicalizer is validated differentially
  against libxml2, and the complete flow is proven against pinned Keycloak
  26.0. Other identity providers remain unproven.
- Marketing website under `website/`, built with Tachyon and DuVay: a home
  page, a getting-started guide, and a download page, prerendered as static
  files. Everything countable the site claims — the operation count, the SDK
  list — lives in one `facts.js` module that `test/contract/website_test.go`
  joins back to the manifest and `clients/`, so a marketing claim cannot drift
  from the code. The same test
  fails the build on unearned support language such as "OpenID certified" or
  "production ready". Two guide pages — authentication and tokens, and MFA and
  step-up — carry working call sequences for password login, session-to-JWT
  exchange, refresh rotation, TOTP, recovery codes, passkeys, and step-up
  decisions; every snippet was executed against a real engine and a real FYLO
  runtime before it was written down, in all ten languages. Guide pages cover
  concepts, authentication and tokens, MFA and step-up, authorization, and a
  full reason/error-code reference. Three tests hold the site to the code: one
  resolves every SDK method a snippet names against the shim that must define
  it, one checks every guide card links to a route that exists, and one pins
  the error reference to the engine's own constants in both directions — an
  undocumented code and a documented non-code both fail the build.
- Responsive layer for the website: fluid spacing and type via `clamp()`, with
  media queries only where layout has to change shape — the architecture
  diagram becomes a column with downward arrows, reference tables stack into
  label/value pairs, the install command wraps so its copy affordance cannot
  scroll out of reach, and every control is at least 44px on a touch target.
  Verified free of horizontal overflow at 320, 375, 414, 768, 834, 1024, 1920,
  and 2560 across all eight pages. Fixes a pre-existing bug where the sticky
  header never stuck: Tachyon wraps each component in its own element, and the
  wrapper was exactly as tall as the header, so `position: sticky` was a no-op.
- Visual pass over the website: a layered background (fixed aurora plus a
  masked grid), one shared depth ramp for every raised surface, gradient
  buttons with a lit top edge, the install command rebuilt as a real control
  rather than a caption, the four headline numbers gathered into one panel,
  language tabs as a segmented control, and accented inline code. Both themes
  carry the same ramp.
- Environment-variable configuration so a deployed application needs no
  SESAME-specific arguments: `SESAME_DEPLOYMENT`, `FYLO_BINARY`, and
  `FYLO_ROOT` are read by the engine (so all ten SDKs support them without
  implementing anything), and `SESAME_BINARY` is read by each shim. The two
  FYLO settings reuse FYLO's own variable names rather than taking a `SESAME_`
  prefix, so one variable configures both SESAME and the FYLO child it spawns;
  SESAME does not adopt FYLO's `./.fylo-data` default for an unset root. An
  explicit flag or option always wins. A missing or uninitialised deployment
  is now refused at startup with a message naming which of the two problems it
  is and the command that fixes it, and every shim captures the engine's
  startup diagnostics so that message reaches the caller instead of being
  discarded. Documented in [docs/CONFIGURATION.md](docs/CONFIGURATION.md),
  which also records the key boundary and why passwords have no key or pepper
  to supply.
- README rewritten against the current engine. The previous one still said no
  identity protocol was implemented — four phases out of date — and nothing
  failed when it drifted, so `test/contract/readme_test.go` now checks its
  operation count against the manifest, that every shipped SDK is linked, that
  every local link resolves, and that no unearned support claim appears.
- `decideForSession` on the seven SDK shims whose positional `decide()` could
  not carry a session, so every shim can now express a step-up decision
  through a typed method rather than the raw request escape hatch. A contract
  test asserts all ten can reach the capability; verified against a real engine
  in both directions — a password-only session denies, an MFA session allows.
- Per-group coverage floors enforced in CI by `tools/coverage`, with the
  profile uploaded as a build artifact.
- Device authorization grant (RFC 8628) as a full vertical: domain,
  application layer with durable projections, `oidc.device_authorize`,
  `device_lookup`, `device_approve` and `device_deny` operations, a
  `sesame device` CLI family, typed methods in all ten SDKs, and real-FYLO
  restart evidence proving a pending device, an approval, and a spent device
  code all replay. The user code is drawn from a confusable-free alphabet by
  rejection sampling rather than a modulus, and is attempt-bounded and
  short-lived because it is the only guessable credential in SESAME.
  `authorization_pending` is the only polling outcome that invites another
  poll; refusal, expiry and never-existed collapse into one `access_denied`
  so the token endpoint cannot be used to probe the verification surface.
- Apache-2.0 project governance and contribution policies.
- Initial Go engine, CLI, and NDJSON machine protocol.
- Initial process-backed Go client shim.
- Contract, package, and compiled-binary tests.
- Host-owned-server architecture with no standalone SESAME network listener.
- Fail-closed FYLO subprocess adapter with bounded protocol and diagnostic
  handling.
- Disposable FYLO viability runner and opt-in real-runtime integration test.
- FYLO runtime handshake validation, exact frame-limit negotiation, artifact
  digest reporting, and exclusive-root contention evidence.
- Complete disposable Phase 1 FYLO profile covering exact-winner concurrency,
  hash-chained replay, verified snapshots, revocation and migration
  equivalence, crash boundaries, corruption, index rebuild, cold restore,
  bounded mixed admission, cancellation, restart, and latency/leak evidence.
- Native FYLO evidence matrix separating development observations from
  production platform-support claims.
- Bounded cursor-paged document retrieval in the FYLO adapter with fail-closed
  page-consistency checks, typed invalid-cursor detection, and mandatory
  `queryPagination` capability validation in the runtime handshake.
- Security-event ledger replay through bounded cursor pages instead of one
  unpaged query, with paged/unpaged equivalence and invalid-cursor rejection
  evidence in the full FYLO profile.
- Tenant bootstrap vertical slice: tenant domain model with random public
  identifiers, a production hash-chained security-event ledger over FYLO with
  fail-closed replay verification, an idempotent single-writer bootstrap
  command, `tenant.bootstrap`/`tenant.get` machine operations with stable
  error codes, `sesame tenant` CLI commands, storage-aware readiness, Go SDK
  tenant methods, and a real-runtime restart-survival integration test.
- Deployment key boundary: `sesame init` creates a validated deployment
  directory holding the snapshot MAC key outside FYLO documents with
  fail-closed permission and schema checks, and `sesame doctor` reports FYLO
  identity, ledger verification, and snapshot/full-replay equivalence.
- HMAC-verified projection snapshots that bound ledger replay, fail closed on
  tampering or a wrong key, and are written automatically after successful
  commands; keyless deployments ignore snapshots and replay the full ledger.
- Registered-event-type and schema-version upcast gate on ledger replay;
  unknown types or versions fail closed.
- Structured JSON diagnostics on stderr with a compiled-binary secret-canary
  test proving key material never reaches any output stream.
- `system.metrics` machine operation reporting uptime, runtime stats, storage
  state, and per-operation request and per-code error counters.
- Phase 2 exit-gate lifecycle evidence for the bootstrap event: the opt-in
  real-runtime suite now also proves derived-index rebuild, cold restore into
  a distinct root, and an environment-gated interrupted upgrade from the
  pinned FYLO release to a next-version candidate that must replay identical
  tenant decisions and continue the same hash chain.

- Machine-request tracing: one structured span per request with operation,
  request ID, outcome, error code, and duration, without parameters or
  results.
- Tag-triggered release workflow producing cross-compiled artifacts with
  `SHA256SUMS`, an SPDX SBOM, and verified signed GitHub build attestations.
- Principal and identifier vertical slice: human and workload principals with
  random public IDs, atomic tenant-scoped identifier claims with a stable
  `identifier_conflict` code, durable idempotent suspension,
  `principal.create`/`principal.get`/`principal.suspend` machine operations,
  `sesame principal` CLI commands, Go SDK methods, snapshot-state coverage,
  and real-runtime crash-replay evidence.

- Authorization vertical slice: tenant-scoped immutable roles with a
  deterministic pattern language, explicit grants with exactly-once
  uniqueness, durable grant revocation, and a default-deny
  `authorize.decide`/`authorize.decide_batch` decision API with stable reason
  codes, random decision IDs, and a replayable policy version that fails
  closed on stale pins — exposed through machine operations, `sesame
  role|grant|authorize` CLI commands, and the Go SDK, with a golden decision
  corpus and real-runtime revocation-durability evidence. Groups are
  deliberately deferred to a following slice.
- Storage schemas aligned with FYLO's document model, which deliberately
  rejects embedded arrays of objects (such data belongs in its own
  collection): role permissions are stored as flat `action=resource` pairs
  inside their single atomic event, snapshot state is an opaque MAC-verified
  JSON string, and the fake test runtime enforces the same rule so
  non-conforming schemas fail in unit tests.

- Groups: tenant-scoped named groups, durable membership add and remove, and
  role grants to a group that apply to present and future members with a
  distinct `allow_group_grant` decision reason.
- Converging `admin.bootstrap` command that establishes a tenant,
  administrator role, administrator principal, and grant, creating only what
  is missing so an interrupted bootstrap can be retried safely.
- Node SDK (`clients/node`) with TypeScript declarations and Python SDK
  (`clients/python`), both standard-library-only, plus one shared SDK
  contract corpus that Go, Node, and Python each run against real compiled
  binaries in CI.
- Example host server (`examples/hostserver`) showing a developer-owned HTTP
  listener with fail-closed SESAME decision middleware.

- FYLO handshake failures now carry the child's exit status and stderr tail
  so a refused root or an early child exit is diagnosable from the error
  alone.

- Equality-only context conditions on permissions with a `deny_missing_context`
  reason that names the absent attribute, reported only when supplying it
  would change the outcome.
- Deterministic golden decision corpus as data in
  `api/machine/v1/decisions.golden.json`, asserted by the engine test and by
  the Go, Node, and Python SDK suites so the semantics have one definition.
- Phase 3 exit-gate property tests for default deny, precedence, missing
  attributes, tenant isolation, and version pinning over seeded
  pseudo-random inputs.

- Phase 4 authentication foundation: Argon2id password verifiers with an
  explicit parameter-upgrade path that rehashes transparently on next login,
  a persisted authentication transaction state machine with bounded attempts
  and lifetime whose transitions the engine alone decides, and bounded
  revocable sessions whose bearer secrets are stored only as digests.
  Authentication never reveals whether an identifier exists: an unresolved
  transaction runs to the same outcome against a decoy verifier, so neither
  the response nor the hashing cost distinguishes it.
- Read-only guard on every identity command: a projection built without a
  ledger now refuses writes with `ErrReadOnly` instead of panicking.

- Authentication surfaces: `authenticator.set_password`, `authn.begin`,
  `authn.verify_password`, `authn.complete`, `session.verify`, and
  `session.revoke` machine operations with stable codes, `sesame authn` and
  `sesame session` CLI commands that read credentials from environment
  variables rather than flags, and matching methods in the Go, Node, and
  Python SDKs. A session's stored digest never crosses the protocol
  boundary, and no operation echoes a password.

- Seven further SDK shims — Rust, Java, Kotlin, C#, PHP, Ruby, and Dart —
  bringing SESAME to ten languages. Each is standard-library-only, spawns
  `sesame exec --loop`, maps stable errors to a typed exception, and runs the
  same contract scenario against real compiled binaries in CI. Kotlin and
  Dart are server-side clients rather than the on-device variants FYLO ships,
  and SESAME deliberately has no browser or mobile client: it is a supervised
  server-side process with no embeddable engine.

- TOTP second factor (RFC 6238, HMAC-SHA1, six digits, thirty-second step)
  with two-step enrollment: the secret is returned once and the factor stays
  unusable until a code proves it. A successful code spends its time-step
  counter durably, so a code observed in transit cannot be replayed inside
  its own window, and the refusal survives restart and replay. A second
  factor raises session assurance to `mfa`.
- Sealed-secret facility: credentials that must be read back rather than
  compared — currently TOTP shared secrets — are sealed with AES-256-GCM
  under a new deployment `secrets.key`, held outside every FYLO document.
  Operations needing it fail closed without a deployment. This is SESAME's
  own envelope rather than FYLO field encryption, which cannot decrypt on
  read-only replay (FYLO issue #84).

- Recovery codes: ten single-use backup codes returned once and stored only
  as digests, spent durably so one cannot be used twice across a restart,
  and usable as a second factor when the TOTP device is gone. Reissuing
  retires every previous code.
- Step-up enforcement at the decision boundary: a decision may carry a
  session instead of naming a tenant and principal, and the engine derives
  `session.assurance` from the verified session rather than trusting a
  caller-asserted attribute, so a permission can require `mfa`. Attributes
  under the reserved `session.` prefix are rejected if supplied, and an
  unusable session denies with `deny_session_invalid`.
- Token signing boundary: an ES256 signing key generated by `sesame init` into
  the deployment key directory, never into a FYLO document, with a `kid`
  derived from the public key. Verification accepts ES256 and the configured
  `kid` only, so `alg: none` and symmetric-algorithm confusion have nothing to
  act on. `token.jwks` and `sesame token jwks` publish the public half; both
  fail closed with `signing_not_configured` rather than serving an empty key
  set.
- OIDC relying-party registration: confidential and public clients with
  exactly matched redirect URIs — wildcards, prefixes, and non-loopback `http`
  are refused at registration — Argon2id-hashed client secrets returned once,
  rotation that kills the previous secret at the same moment, and durable
  idempotent disablement. There is no grant-type field: the implicit and
  password grants are not modelled at all.
- Authorization code flow with mandatory S256 PKCE and the external
  interaction contract: `oidc.authorize` validates the whole request before a
  login page exists, returns a handle whose secret authorizes completion,
  `oidc.interaction_complete` trades a verified session for a code bound to
  the interaction's own redirect URI, and `oidc.token` re-checks every binding
  before minting ES256 access and ID tokens. Codes are single-use and live 60
  seconds; a revoked session or suspended principal stops the exchange; every
  failure returns one undifferentiated `invalid_grant`. The issuer comes from
  the deployment configuration (`sesame init --issuer`) and issuance fails
  closed without it.
- Rotating refresh tokens with reuse detection: a client registered for
  `offline_access` receives a refresh token that rotates on every use.
  Presenting a spent token means two parties hold tokens from one family, so
  the whole family is revoked durably — including the successor a legitimate
  client holds — and the spent state survives replay and snapshot restore. A
  refresh may narrow its scopes and never widen them, dies with a revoked
  session, suspended principal, or disabled client, and is bounded absolutely
  at 30 days per token and 90 days per family. Session *expiry* does not end
  it: `offline_access` is for when the user is away. `oidc.refresh_family_revoke`
  and `sesame token revoke-family` are the durable logout primitive.
- OIDC discovery, introspection, and revocation. The discovery document's
  capability lists are the same slices the request validators read, so an
  advertised response type, grant, PKCE method, or signing algorithm is by
  construction one the engine accepts — and the host names its own route
  paths, which the engine composes under the configured issuer and refuses if
  they would leave that origin. `oidc.introspect` reports live grant state
  rather than only signature validity, so a revoked session or suspended
  principal makes an otherwise-valid access token inactive; an inactive answer
  carries nothing but the flag. `oidc.revoke` ends a refresh family and
  acknowledges an unknown or unrecallable token identically, per RFC 7009.
- Consent for third-party OIDC clients. Registration declares which scopes a
  client *may* request — an administrator's decision — but a client registered
  as `third_party` now cannot obtain an authorization code until the principal
  has agreed, recorded durably per principal and client. The gate compares the
  agreement against the scopes actually requested rather than the ones
  registered, so a narrower consent cannot carry a wider request; re-granting
  merges; and a principal can never agree to more than the client is
  registered for. An omitted audience defaults to `third_party`, the stricter
  rule. Withdrawal is durable, idempotent, and revokes every refresh family
  that client holds for that principal, so a taken-back consent also stops
  live tokens. `consent_required` is a distinct code the host acts on by
  showing a consent screen; the interaction stays live.
- Passkeys (WebAuthn), the first phishing-resistant factor: the authenticator
  signs over the origin the browser is actually talking to, so an assertion
  collected by a replica of the login page is refused. Scope is `none`
  attestation and COSE ES256 only — any other attestation format is refused
  rather than accepted unverified. Challenges are engine-issued and
  single-use: a registration challenge is spent even by a failed attempt, and
  an authentication challenge lives on the durable transaction so an assertion
  cannot be replayed into another. A user-verified passkey establishes `mfa`
  assurance on its own with no prior factor; without user verification it is
  possession alone. A sign counter that fails to advance is treated as a
  cloned authenticator, durably. CBOR is decoded by a deliberately tiny reader
  that refuses indefinite lengths, tags, floats, duplicate map keys, and
  unbounded nesting, rather than by adding a general CBOR dependency; it is
  fuzzed along with the registration verifier.
- RP-initiated logout: an `id_token_hint` names the session to end, and
  revoking that session ends every refresh grant resting on it, so one call is
  a complete logout rather than a gesture. The audience is read from the hint
  rather than supplied alongside it, a hint whose subject does not own the
  session it names ends nothing, and post-logout redirect URIs are registered
  per client and matched exactly. An expired hint is accepted deliberately —
  it authorizes nothing, and a user reaching for "sign out" often does so
  because their tokens have aged.
- Protocol adversarial suite (`test/adversarial`): ten attack families over
  twenty-three cases, every one run against a real compiled binary over the
  shipped machine protocol against a real deployment, covering replay,
  confused deputy, open redirect, CSRF and PKCE downgrade, cross-tenant
  substitution, recovery bypass, algorithm confusion, identifier enumeration,
  and immediate suspension and revocation. It is a named CI step. Three
  architecture tests inspect the linked dependency graph of the engine binary
  to prove it opens no listener, renders no UI, and has gained no module
  outside the reviewed set.
- Canonical operation manifest (`api/machine/v1/operations.json`) recording all
  53 machine operations and, per SDK, exactly which ones lack a typed method.
  Three tests make it binding rather than decorative: it is checked against the
  engine's dispatch table by parsing the processor, against the protocol
  reference so nothing ships undocumented, and against each SDK's source so a
  gap cannot be opened or closed silently. Phase 5's "no undocumented
  divergence" is now a test rather than a promise, and SDK parity is a list
  that can only shrink deliberately.
- Full SDK surface parity: all ten shims — Go, Node, Python, Rust, Java,
  Kotlin, C#, PHP, Ruby, and Dart — now expose a typed method for every one of
  the 53 machine operations, with zero declared gaps in the manifest. Each
  addition follows its own language's existing idiom, adds no dependency
  (WebAuthn binary values are base64-encoded by each standard library, or by a
  hand-written encoder in Rust checked against a reference), and every shim's
  contract corpus still passes against a real compiled binary.
- Engine compatibility handshake: `system.version` now also reports the machine
  protocol version and every operation the binary routes, and all ten SDKs
  verify it at startup — refusing an engine speaking a different protocol
  rather than discovering the mismatch partway through a login. The error names
  both sides. Each SDK also exposes `requireOperations`, so an application can
  assert at startup that what it depends on exists. The reported list, the
  dispatch table, and `operations.json` are asserted against each other, so a
  client trusting the engine's own answer is trusting something checked.
- Registry-free SDK distribution, matching [FYLO](https://fylo.del.ma)'s model
  exactly: every shim is a single dependency-free file, each release ships
  `sesame-clients.tar.gz` beside the engine binaries, and a developer copies
  the one file for their language into their project. **No package registry
  and no per-ecosystem package manifest.** Go is the single exception,
  resolving from the module tag because vendoring it would be worse. This buys
  one release, one version, one provenance chain, no publishing credentials to
  hold, and one mental model for anyone using both projects.
  [docs/SDK_DISTRIBUTION.md](docs/SDK_DISTRIBUTION.md) records the install
  steps, verification, and what the model costs — no dependency resolver, no
  lockfile entry, no transitive install.
- `tools/package-clients.sh`, which builds the client bundle for both CI and
  the release so the two cannot drift. It excludes build output and then fails
  if any compiled artifact survives: a plain `tar clients` sweeps in whatever
  the contract tests last compiled, so a release cut after someone ran the C#
  suite would have shipped `.dll` and `.pdb` files inside a bundle advertised
  as source.
- `tools/verify-sdk-install.sh`, which proves each SDK can be *consumed* rather
  than merely shipped: it builds the client tarball, extracts it, and for all
  ten languages copies the shim into a throwaway project and runs code against
  it. With no manifest declaring a release's contents, this is the only thing
  between a tag and a tarball that silently lacks someone's language. CI runs
  it on every pull request, and the release workflow separately asserts the
  archive contains every expected file before anything is attested.
- Phase 6 slice 1, inbound OIDC federation: the domain layer, with
  [ADR 0004](docs/adr/0004-federation-egress-boundary.md) settling the egress
  boundary. The engine performs no network I/O — it names the URL, the host
  fetches it, and every response is validated in the engine as untrusted
  input, so `net/http` stays out of the dependency graph and the Phase 4
  no-listener evidence survives. Includes discovery-document validation that
  pins every endpoint to the registered issuer's origin, JWKS parsing with
  bounded key counts and no duplicate `kid`, and external ID token
  verification against a closed allowlist (RS256/384/512, ES256/384/512) with
  the key pinned by `kid`, a 2048-bit RSA floor, on-curve checks, and
  `iss`/`aud`/`azp`/`exp`/`iat`/`nbf`/`nonce` enforced. Federated login
  transactions are persisted, single-use, and carry mandatory outbound PKCE.
  The application layer is live: provider registration and configuration,
  login start/exchange/complete, verified-email linking with just-in-time
  provisioning, projections, and snapshot round-trip, covered by tests for
  single-use replay, expiry, cross-login nonce replay, cross-tenant isolation,
  suspended principals, and unverified-email account takeover. Surfaces —
  machine operations, CLI, SDKs — are not built yet; see the Phase 6 status in
  the project plan.
- The federation machine surface: seven operations with stable error codes,
  protocol-reference entries, and methods on all ten SDK shims. Every rejected
  assertion returns one code whatever the cause, so a caller cannot map the
  flow by probing it.
- `federation.provider_disable` and `sesame federation provider-disable`, the
  remedy for a compromised provider: new logins stop immediately and an
  in-flight one cannot complete, while existing links and sessions survive so
  the operator decides separately whether to revoke them.
- Registered the eight federation event types in `audit.KnownEventTypes`. They
  were missing, so a deployment using federation would have refused to replay
  its own ledger after a restart. Found by the real-FYLO restart test; the
  in-memory fake does not validate the registry.
- Twenty-five federation attack cases in `test/adversarial`, driven through a
  real compiled binary over the shipped protocol: algorithm confusion,
  assertion replay, hostile discovery documents including loopback and
  link-local SSRF targets, cross-tenant substitution, account takeover through
  an unverified email, and a disabled provider stopping an in-flight login.
- A distinct `federated` assurance level. A provider's assertion is not the
  same as a locally proven factor, and reusing `password` for it would let a
  federated session silently satisfy a step-up requirement.
- Length-prefixed the provider identifier in `federation.SubjectHash`. With a
  plain separator, `("idp_a", "b\x00c")` and `("idp_a\x00b", "c")` hashed
  identically, so one provider's subject could collide with another's.
  Validated provider identifiers cannot contain the separator today, but a
  hash whose injectivity depends on a caller's validation is one assumption
  away from breaking. Found by the test written to assert it could not happen.
- `tools/crap`, which measures the Change Risk Anti-Patterns score for every
  function by joining cyclomatic complexity from the AST with per-function
  statement coverage. Current state: 241 of 593 functions exceed CRAP 5, and
  171 exceed cyclomatic complexity 5 — which is the binding constraint,
  because the metric's additive term means a function of complexity *n* can
  never score below *n* no matter how well tested. The tool fails loudly when
  its two inputs do not join, since that failure would otherwise report every
  function as uncovered and every score as inflated.
- A structural guard that every projection is reachable from the replay
  table. An `apply` function no event type routes to is a forgotten
  projection, and a forgotten projection means a restart quietly loses
  security state.
- Phase 6 slice 2, SCIM 2.0 provisioning: the domain layer. Provisioning
  clients with SHA-256-hashed bearer tokens and a separate `CanManageGroups`
  gate, because group membership drives authorization decisions and a
  directory sync that can move people between groups is a privilege-granting
  operation. User parsing treats an absent `active` as active per RFC 7643 —
  the opposite reading would suspend every user a provider syncs without that
  attribute. PATCH and filter support are deliberately bounded subsets that
  refuse with a reason rather than partially honouring an expression SESAME
  does not evaluate. Surfaces are not built yet; see the Phase 6 status in the
  project plan. The application layer is live: create, read, filtered and
  paginated list, bounded PATCH, deprovisioning, and snapshot round-trip.
  SCIM DELETE maps to suspension rather than erasure so the audit trail keeps
  its subject, and PATCH can deactivate but never reactivate so a directory
  sync cannot undo an administrator's suspension. Eight machine operations,
  stable error codes, and methods on all ten SDK shims. Every resource
  operation carries the bearer token as a parameter, so the engine always
  authenticates and a host cannot forget to. Token rotation invalidates the
  previous token immediately: an overlap window is what an attacker holding a
  leaked credential would use. `sesame provisioning` CLI commands limited to
  the administrative operations, [docs/PROVISIONING.md](docs/PROVISIONING.md),
  real-FYLO restart evidence, and thirty adversarial cases driven through a
  real compiled binary.
- SCIM Group resource provisioning, which is what `CanManageGroups` gates. A
  provisioned group is created through the same command an administrator uses,
  so an authorization decision cannot tell whether it arrived by sync or by
  hand. Group PATCH reads the one value-path shape SESAME refuses elsewhere —
  `members[value eq "X"]` — because directories express member removal in two
  incompatible ways and supporting one works with half the market; it is
  matched as a literal shape, not evaluated as an expression. Membership
  changes are idempotent, because directories reconcile by re-sending the
  whole desired state. Deprovisioning a group empties it rather than deleting
  it, so its grants stay readable and an operator can see what access went.
  Five machine operations, methods on all ten SDK shims, adversarial cases,
  and operator documentation. The `CanManageGroups` gate is taken before any
  payload is parsed, so an ungranted client learns nothing about whether its
  request was well-formed. Real-FYLO restart evidence asks the decision engine
  rather than reading the projection, and covers both directions: membership
  that does not replay denies everybody who held access through the group, and
  a removal that does not replay grants access to people the directory removed.
- Phase 6 slice 3, SAML 2.0: the signature-verification core, with
  [ADR 0005](docs/adr/0005-saml-signature-verification.md). Exclusive XML
  canonicalization and XML Signature verification are implemented in-tree
  rather than by adding a dependency, after measuring that `encoding/xml`'s
  `RawToken()` preserves namespace prefixes and that its parser refuses custom
  entity references. Verification returns the byte range of the signed
  element and the caller reads only that, so XML Signature Wrapping is
  structurally impossible rather than filtered; six published wrapping shapes
  are refused as ambiguous, and those refusals hold independently of
  canonicalization correctness. The allowlist excludes SHA-1 and every HMAC
  method. The canonicalizer is validated differentially against libxml2's
  `xmllint --exc-c14n` over nineteen cases, because a package that verifies
  its own signer proves nothing; that test was confirmed to bite by removing
  attribute sorting. Verification is additionally proven end to end against a
  signature the package did not help produce — the test signer canonicalizes
  with xmllint and only then signs — and tampering with a signed assertion's
  subject, window, audience, or recipient is caught by the digest. The
  assertion domain enforces the three questions a signature does not answer:
  was this written for SESAME, for this login, and now. Interoperability with
  a **real** identity provider is not yet proven, so SAML support is not
  claimed.

### Changed

- Replaced the machine processor's 53-arm dispatch switch and the identity
  service's 41-arm replay switch with lookup tables. Both were pure dispatch —
  one line per operation, no interacting state — but to any complexity budget
  a 53-arm switch is one function of cyclomatic complexity 53, indistinguish-
  able from 53 nested branches. `dispatch` went from CRAP 142 to 6.3;
  `NewFromSnapshot` from 335 to 154. The contract test that parses the
  dispatch table from the AST was updated to read map keys and re-verified by
  injecting a phantom operation.

- Flattened every shim to one file per language, matching FYLO's layout:
  `node/sesame.mjs`, `python/sesame.py`, `ruby/sesame.rb`, `dart/sesame.dart`,
  and `Sesame.java`/`Sesame.kt` at the root of their directories. The Java and
  Kotlin shims keep `package ma.del.sesame` rather than FYLO's default
  package, because a default-package class cannot be imported by a class that
  has one, which would make the shim unusable in most real projects. Every
  shim's contract corpus still passes against a real compiled binary.
- Corrected the Node README, whose example still called `Client.start` without
  awaiting it after that call became asynchronous.

### Fixed

- Classified a SCIM PATCH value path (`emails[type eq "work"]`) as unsupported
  rather than malformed. It is well-formed SCIM that SESAME will not act on,
  and the caller needs to tell that apart from a broken request: one is fixed
  in the directory's configuration, the other is a bug. Found by the
  adversarial suite, which asserts the wire code rather than just a refusal.
- Rewrote `TestQueuedRequestHonorsItsOwnCancellation` to assert its property
  relatively instead of against a 150 ms wall-clock bound. The property — a
  queued request observes its own deadline rather than waiting for the request
  ahead of it — is now stated as "the head-of-line request is still in flight",
  which scheduling delay under `-race` cannot breach. It had failed twice under
  full-suite load with two different symptoms.

- Restored the two group-membership event types to the replay table. Converting
  the replay switch to a map dropped them, because they shared one multi-value
  `case` arm that a mechanical extraction did not match. Nothing failed to
  compile; the only symptom was a projection that silently stopped applying,
  caught by the one existing test that replays a membership change. The
  structural guard added alongside would have caught it directly — and its own
  first version did not, because it scanned every `apply*` reference in the
  package rather than only the replay table, and every projection is also
  called by the command that appends its event.

- The Node client now exports `PROTOCOL_VERSION`. Every other shim exposes it,
  so an application could ask which protocol its client speaks in nine
  languages and not the tenth. Found by consuming the published package rather
  than by reading it: the operation-parity manifest covers operations, and this
  is a constant.

- Pinned the FYLO release candidate to signed v26.30.06 (release commit
  `39f57b5c`), after verifying its checksum against the release `SHA256SUMS`
  and confirming the signed GitHub attestation covers the `fylo-macos-arm64`
  subject digest in use, then passing ten consecutive native macOS arm64
  full-profile runs and the opt-in integration suite both with and without the
  development-build exception.
- Re-measured FYLO at-rest field encryption against v26.30.06 and recorded the
  result: FYLO [#84](https://github.com/d31ma/FYLO/issues/84) is fixed, so a
  read-only process now decrypts correctly without a prior write, and a wrong
  key fails closed with a typed `EDECRYPTFAILED` instead of silently returning
  ciphertext. Adoption was then declined: SESAME stores snapshot state as one
  opaque JSON string, so encrypting the event collection's verifier field would
  leave the identical values in cleartext inside every snapshot, and SESAME
  already owns a better-fitting AES-256-GCM sealing primitive that covers
  snapshot state and fails closed without its key where FYLO's fails open.
  Password verifiers continue to rest on Argon2id alone.
- Pinned the FYLO release candidate to signed v26.30.05 (release commit
  `f30ee792`), replacing the unversioned development candidate, after
  verifying its checksum and GitHub build attestation and passing ten
  consecutive native macOS arm64 full-profile runs without a
  development-build exception.

### Fixed

- Prevented an already-cancelled FYLO request from racing gate acquisition and
  terminating an otherwise healthy child process.

[Unreleased]: https://github.com/d31ma/sesame/commits/main
