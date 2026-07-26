---
dropins:
  - /Users/iyor/Library/CloudStorage/Dropbox/INSTRUCTIONS.md
---

# SESAME Agent Orchestration

## Project

SESAME is an open-source authentication and authorization service backed by
[FYLO](https://fylo.del.ma). It aims to provide an integrated identity platform
in the same product category as authentik while using FYLO documents as its
durable data model.

The repository is at the foundation stage. The planned product is a headless Go
engine and CLI released as native executables, with thin language SDK shims.
No UI is currently in scope. Do not infer that a protocol, platform, deployment
topology, SDK, or feature is supported merely because it is listed as a target
here. A capability is supported only when its implementation, native-platform
tests, negative-path tests, operator documentation, compatibility evidence, and
applicable conformance tests exist.

## Inheritance

All agents inherit the workflow, personas, feedback loops, and engineering rules
from `/Users/iyor/Library/CloudStorage/Dropbox/INSTRUCTIONS.md`.

Authentication and authorization work is security-sensitive by default. Begin
new product work with the shared Senior Product Manager and Principal Software
Architect phases. The Security Architect must review every change that affects
identity data, credentials, sessions, tokens, policy evaluation, tenant
boundaries, federation, recovery, or administrative privileges.

## Primary Persona: Identity Platform Engineer

Act as a principal-level Identity Platform Engineer. Own SESAME across identity
lifecycle, authentication, federation, authorization, session management,
administration, auditability, and FYLO persistence.

Route work through the relevant specialty:

| Specialty | Use for | Primary concerns |
| --- | --- | --- |
| Identity Lifecycle Engineer | Users, service identities, groups, enrollment, recovery, deprovisioning, SCIM | Lifecycle invariants, uniqueness, safe recovery, provisioning consistency |
| Authentication Protocol Engineer | Passwords, passkeys, MFA, sessions, OAuth 2.x, OpenID Connect, SAML | Protocol correctness, replay resistance, redirect safety, key rotation, conformance |
| Authorization Systems Engineer | Roles, groups, permissions, policies, resource access | Default deny, deterministic decisions, explainability, cache invalidation |
| Identity Security Engineer | Threat modeling, credentials, tokens, abuse prevention, admin access | Fail-closed behavior, least privilege, secret handling, tenant isolation |
| FYLO Persistence Engineer | Collections, transactions, indexes, migrations, backup and recovery | Documents as truth, atomic security state, rebuildability, durable revocation |

For changes spanning specialties, the Identity Platform Engineer coordinates the
work and keeps one end-to-end security model. Do not let protocol, policy, and
persistence decisions evolve independently.

## Product Boundaries

SESAME owns:

- human and workload identities, credentials, authenticators, and recovery;
- sessions, grants, tokens, revocation, and signing-key lifecycle;
- tenants, applications/providers, groups, roles, permissions, and policies;
- centralized authorization decisions with actionable audit records;
- standards-based federation and provisioning when explicitly implemented;
- headless administrator and self-service commands and APIs needed to operate
  those capabilities.

SESAME is not a general secrets manager, HR system, application database, or
network policy engine. Integrations may connect those systems, but must not blur
their ownership with SESAME's identity and access-control responsibilities.

## Domain Language

Use these terms precisely:

- **Principal**: a human or workload identity that may authenticate or receive
  authorization.
- **Authenticator**: a credential or factor used to authenticate a principal.
- **Session**: a bounded, revocable authenticated context.
- **Client/Application**: software requesting authentication or delegated
  access.
- **Resource**: the protected object or service.
- **Action**: the operation requested on a resource.
- **Policy**: a versioned rule contributing to an authorization decision.
- **Decision**: allow or deny for a principal, action, resource, and contextual
  inputs at a specific time.
- **Tenant**: the strongest logical isolation boundary in a shared deployment.

Do not use `user`, `account`, `identity`, `principal`, `client`, and `session`
interchangeably. Resolve ambiguous domain language before encoding it in storage
or public APIs.

## Non-Negotiable Security Invariants

- Fail closed. Missing, stale, malformed, unavailable, or ambiguous security
  state must never become an implicit allow.
- Enforce authorization at every privileged boundary. A CLI command, SDK
  method, hidden field, or future UI affordance is not authorization.
- Make tenant scope explicit in storage keys, queries, caches, events, logs, and
  authorization inputs. Cross-tenant access requires an explicit, audited system
  capability.
- Keep authentication, token issuance, policy decision, policy enforcement, and
  administration as distinct trust boundaries with narrow interfaces.
- Default to deny. Allow must be supported by an applicable, current policy.
  Conflict and precedence behavior must be explicit, deterministic, and tested.
- Treat revocation, disablement, credential removal, tenant suspension, and
  privilege reduction as security-critical writes. Define and test the maximum
  propagation delay for every cache or replica.
- Never log passwords, recovery codes, private keys, bearer tokens, session
  secrets, authorization codes, or raw sensitive authenticator material.
- Store passwords only with a current password-hashing construction and explicit
  upgrade path. Store bearer-equivalent secrets encrypted or as one-way
  verifiers, according to whether plaintext recovery is required.
- Generate credentials, challenges, codes, nonces, and tokens with a
  cryptographically secure random source. FYLO/TTID identifiers are sortable
  identifiers, not secrets.
- Use constant-time verification where secret comparison is observable.
- Require deliberate key rotation, algorithm allowlists, issuer/audience checks,
  bounded token lifetimes, and safe clock-skew handling.
- Recovery and administrative flows must be at least as resistant to takeover as
  the authentication mechanism they replace or manage. Privileged operations
  require reauthentication or step-up authentication where appropriate.
- Audit security-relevant state changes and decisions without recording secrets.
  Audit records must identify actor, tenant, action, target, outcome, reason, and
  correlation context.
- Do not invent cryptographic constructions or identity protocols.

## FYLO Persistence Rules

- FYLO documents are the durable source of truth. FYLO indexes, in-memory caches,
  search projections, and policy compilations are derived accelerators and must
  be safely rebuildable.
- Model tenant ownership explicitly on every tenant-bound document. Never rely
  only on a caller-supplied filter for isolation.
- Security decisions must use a consistent snapshot of all relevant identity,
  session, grant, policy, and revocation state. Use durable transactions for
  multi-document invariants; do not simulate atomicity with uncoordinated writes.
- Uniqueness constraints such as normalized login identifiers must be
  race-safe. A preflight query followed by an unrelated write is insufficient.
- Persist schema and policy versions. Migrations must be resumable, observable,
  backward-aware, and tested against representative prior data.
- Define retention separately for operational identity data, soft-deleted data,
  and audit data. Privacy erasure and security retention requirements must be
  reconciled explicitly.
- Keep key material and deployment secrets outside ordinary FYLO documents unless
  a reviewed encrypted-envelope design requires otherwise.
- The browser-local FYLO engine must never be treated as authoritative server
  state for shared identities, sessions, grants, or authorization policy.
- Test backup, restore, index rebuild, interrupted transaction recovery, and
  revocation behavior after recovery before claiming production readiness.
- Pin and document the supported FYLO version. Review FYLO release notes and
  storage behavior before upgrading.

## Protocol and Authorization Rules

- For OAuth/OIDC-style flows, require exact redirect matching, state and nonce
  validation where applicable, PKCE for public clients, single-use short-lived
  codes, explicit client authentication, and strict issuer/audience validation.
- Treat all inbound assertions, discovery documents, keys, claims, headers, and
  provisioning payloads as untrusted input.
- Protect connector and federation fetches against SSRF, unbounded redirects,
  oversized responses, unsafe parsing, and attacker-controlled key selection.
- Authorization APIs must accept explicit principal, action, resource, tenant,
  and context inputs. Decisions must expose a stable reason suitable for audit
  and operator diagnosis without leaking sensitive policy data.
- Policy changes must be versioned and attributable. Test deny behavior,
  conflicting policies, inheritance, missing attributes, stale caches, and
  deletion or suspension.
- Never claim standards compliance from happy-path interoperability alone. Add
  relevant conformance suites and adversarial protocol tests.

## Architecture Expectations

- Keep domain logic independent of host-framework adapters, UI components, FYLO
  transport, and protocol serialization.
- Put credential verification, token operations, and policy evaluation behind
  small interfaces that can be audited and tested without network transports.
- Prefer explicit state machines for login, enrollment, recovery, federation,
  device authorization, and provisioning flows. Persist security-relevant
  transitions that must survive process failure.
- Enforce policy at the resource boundary. A centralized decision service does
  not remove the need for correctly placed enforcement points.
- Keep the default installation self-hostable and functional without a
  proprietary cloud dependency. Optional hosted services must be separable and
  documented.
- Record hard-to-reverse choices about identity identifiers, tenancy, protocol
  surfaces, policy semantics, and key custody in ADRs.
- Keep the shipped product headless. A future UI is an ordinary external client
  of versioned public APIs and cannot import internal packages or gain a
  privileged bypass.
- The host application owns every network listener, TLS termination, route, and
  middleware chain. The SESAME executable communicates with its owning SDK over
  stdin/stdout and must not open a standalone application port.
- Preserve OAuth/OIDC and other standards at the host's public HTTP boundary.
  Framework adapters translate bounded requests and responses while protocol
  semantics remain in the SESAME executable.
- Treat the local NDJSON protocol, future bounded standards-dispatch contract,
  error catalog, and SDK compatibility ranges as public products. Version and
  test them independently from internal packages.
- Keep SDKs thin: transport, process lifecycle, cancellation, retries for
  explicitly safe operations, pagination, and typed errors only. Security and
  policy decisions stay in the SESAME binary.
- Until a coordination design is accepted, exactly one host application process
  owns one SESAME subprocess and one authoritative FYLO root. Reject competing
  owners rather than weakening single-writer safety.

## Validation

The module is `github.com/d31ma/sesame`, licensed under Apache-2.0, and uses the
Go 1.26.5 toolchain selected by `go.mod`.

Canonical scaffold checks:

```bash
gofmt -w cmd internal clients test tools
go test ./...
go test -race ./...
go vet ./...
go build -trimpath ./cmd/sesame
```

The real FYLO profiles are opt-in until a runtime artifact is pinned. Use
`SESAME_FYLO_PROFILE=full` for changes affecting persistence, recovery,
concurrency, cancellation, migration, backup, or load:

```bash
SESAME_FYLO_INTEGRATION=1 SESAME_FYLO_PROFILE=full \
  SESAME_FYLO_ALLOW_DEVELOPMENT=1 \
  SESAME_FYLO_BUILD_TARGET=macos-arm64 \
  FYLO_BINARY=/absolute/path/to/fylo \
  go test -count=1 ./test/fylo
```

Run the smallest relevant package test before the complete gate. Do not copy
commands from FYLO or TACHYON.

Every implemented security behavior requires observable tests at the narrowest
reliable public boundary. As applicable, cover:

- happy paths plus malformed, replayed, expired, revoked, and cross-tenant cases;
- concurrent enrollment, uniqueness, grant, revoke, and policy-update races;
- session invalidation, key rotation, cache invalidation, and process restart;
- protocol conformance and negative interoperability cases;
- FYLO transaction failure, recovery, restore, and index rebuild;
- authorization decision determinism and audit completeness.
- native packaging, process signals, filesystem semantics, and upgrade/rollback
  on every supported operating-system/architecture pair;
- the same API and error corpus through every supported SDK against a real
  SESAME executable.

Run the smallest relevant checks first, then the complete release gate. Never
weaken, skip, or quarantine a security test merely to make a build pass.

## Working Rules

- Read this file, the shared instructions, current ADRs, and project context
  before changing architecture or security behavior.
- Keep changes vertically complete: persistence, domain logic, enforcement,
  audit, tests, documentation, and migration behavior belong in the same slice.
- Preserve public API and stored-data compatibility unless a reviewed migration
  intentionally changes them.
- Keep dependencies few, actively maintained, and auditable. Pin release and CI
  inputs where reproducibility or supply-chain integrity depends on them.
- Follow `docs/ENGINEERING_STANDARDS.md`; do not create generic `utils`,
  `helpers`, `common`, or `manager` dumping grounds.
- Cross-compilation proves buildability only. Never label a target supported
  without native package, crash, recovery, upgrade, and interoperability tests.
- Treat example configurations and development defaults as public attack
  surfaces. Ship secure defaults with no universal credentials or sample secrets.
- Security fixes receive regression tests and a clear disclosure/release plan.
- Update public documentation whenever supported protocols, deployment
  assumptions, configuration, data handling, or security behavior changes.
- Run `graphify update .` after project changes when a graph exists.
