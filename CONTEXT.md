# SESAME Domain Context

## Purpose

SESAME is an open-source identity provider and authorization service. FYLO
documents are its durable application-data source of truth. All indexes,
in-memory views, compiled policies, and snapshots are rebuildable projections.

## Core Terms

- **Tenant**: the strongest logical isolation boundary in a shared SESAME
  deployment.
- **Principal**: a human or workload identity.
- **Identifier**: a normalized name, email address, or external subject that
  locates a principal. An identifier is not a credential.
- **Authenticator**: material and metadata used to authenticate a principal,
  such as a passkey, password verifier, or TOTP enrollment.
- **Authentication transaction**: a bounded, persisted state machine that
  proves required factors and produces an authenticated context.
- **Session**: a bounded, revocable authenticated context.
- **Client**: software registered to request authentication or delegated access.
- **Resource**: the protected object or service.
- **Action**: the operation requested on a resource.
- **Grant**: a versioned assignment connecting a principal or group to
  permissions.
- **Policy**: a typed, versioned rule contributing to a decision.
- **Decision**: allow or deny for one tenant, principal, action, resource, and
  context at a specific policy version.
- **Security event**: an append-only durable fact representing an accepted state
  transition and its audit evidence.
- **Projection**: rebuildable current state derived from ordered security events.
- **Connector**: an outbound integration with a separately administered system.
- **Client shim**: a thin language-specific SDK that implements transport,
  lifecycle, and typed error mapping but never reimplements identity,
  authentication, or authorization decisions.
- **Interaction client**: a trusted external application that renders an
  authentication or consent experience while SESAME owns and validates the
  underlying transaction.

## Relationships

- A tenant owns principals, clients, groups, grants, policies, sessions, and
  authentication transactions.
- A principal can claim multiple identifiers and register multiple
  authenticators.
- A client uses one or more explicitly supported protocol configurations.
- A session belongs to one principal and tenant and records its authentication
  assurance.
- A decision evaluates a principal's effective grants and policies against one
  action, resource, and context.
- A security event advances exactly one logical command and is consumed into
  projections.

## Invariants

- Tenant identity is present in every tenant-bound record, event, query, cache
  key, token, and decision request.
- Normalized identifiers are unique within their declared tenant and namespace.
- Authorization is default deny.
- Codes, nonces, token handles, session secrets, recovery codes, and challenges
  use cryptographically secure randomness.
- Authorization codes and rotating refresh tokens are single-use.
- Revocation and privilege reduction never depend only on an eventually
  refreshed cache.
- Sensitive values never enter logs or plaintext audit fields.
- Acknowledged security transitions are durable before externally observable
  success.
- Projections may be discarded and rebuilt without losing authoritative state.
- The first production topology has one writer for an authoritative FYLO root.
- Public contracts are versioned independently from implementation packages.
- SDK behavior is derived from canonical schemas and is verified against a real
  SESAME executable.
- No UI is part of the initial SESAME distribution.

## Explicit Ambiguities

These choices remain open until their ADR or viability gate is accepted:

- policy condition engine;
- the exact external interaction contract required before browser-facing OIDC
  can be considered turnkey;
- the exact bounded standards-dispatch schema and initial host-framework
  adapter matrix;
- support for multiple tenants in one root versus root-level tenant sharding;
- the FYLO throughput ceiling and resulting supported deployment size;
- Windows production support, which is blocked on FYLO backup/restore parity;
- active-passive and active-active topology after FYLO gains the required
  coordination primitives.

Resolved foundation decisions:

- Apache-2.0 license;
- public Go module path `github.com/d31ma/sesame`;
- Go 1.26.5 toolchain for the current scaffold;
- headless CLI and NDJSON surfaces with no bundled UI or standalone network
  listener;
- one host application process owns one SESAME subprocess and one authoritative
  FYLO root in the initial topology.
