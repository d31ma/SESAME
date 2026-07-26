# ADR 0003: Headless Binary and Client Contract

- Status: Accepted
- Date: 2026-07-23
- Accepted: 2026-07-26

## Context

SESAME must be usable as a native executable across common operating systems and
from applications written in several languages. The initial project explicitly
does not include an admin, login, consent, or desktop UI.

Go can produce executables for many OS/architecture pairs, but executable
formats are platform-specific. FYLO is also a separate platform executable,
drives CHEX and TTID executables, and does not currently provide identical
production capabilities on every target. In particular, FYLO publishes a
native-tested Windows x64 binary but documents backup/restore as unavailable on
Windows.

SDKs create another long-lived compatibility surface. If they reproduce domain
logic or track internal Go types, language implementations will drift and a
security fix will require coordinated rewrites.

## Decision

1. Ship one native SESAME executable per supported OS/architecture pair.
2. Package the exact compatible FYLO, CHEX, and TTID executables beside SESAME
   with checksums, licenses, a release manifest, and cryptographic provenance.
3. Distinguish:
   - **buildable**: cross-compilation succeeds;
   - **tested**: core behavior passes on a native runner;
   - **supported**: native package, contract, crash, recovery, upgrade, soak,
     security, and SDK interoperability gates all pass.
4. Keep the product headless. Operators use the CLI; applications use SDKs and
   expose standards endpoints through their existing web servers.
5. Define one executable transport contract: versioned local NDJSON over
   `sesame exec --loop`. The SESAME executable does not open a network listener.
6. Make the host application responsible for TLS, listening sockets, routing,
   middleware, and public request limits.
7. Preserve OAuth/OIDC and later standards endpoints on their standard public
   wire protocols. A future bounded standards-dispatch operation carries the
   necessary request and response data between a host-framework adapter and the
   SESAME subprocess; SDKs do not reimplement protocol semantics.
8. Build SDK shims from shared schemas and a small hand-written transport layer.
   Shims own transport, process lifecycle, deadlines, cancellation, pagination,
   declared-safe retries, and typed error mapping only.
9. Keep authentication, token, policy, authorization, and state-machine
   semantics in the SESAME executable.
10. Require every SDK to pass one black-box contract corpus against real SESAME
   binaries and publish its protocol compatibility range.
11. Until a coordination design is accepted, one host application process owns
    one SESAME subprocess and one authoritative FYLO root. Competing owners fail
    rather than weakening single-writer guarantees.
12. Treat a future UI as a separate unprivileged client. For browser
    authentication, expose a short-lived, audience-bound external interaction
    contract; the renderer cannot choose or bypass security transitions.

## Initial Contract Envelope

The exact schema is deferred to an RFC, but the local protocol must preserve
these semantics:

```json
{
  "protocol_version": "1",
  "request_id": "caller-generated-id",
  "operation": "authorization.decide",
  "parameters": {}
}
```

```json
{
  "protocol_version": "1",
  "request_id": "caller-generated-id",
  "ok": false,
  "error": {
    "code": "tenant_not_found",
    "message": "safe human-readable summary",
    "retryable": false,
    "details": {}
  }
}
```

The machine interface is UTF-8, one bounded JSON object per line. Stdout carries
protocol frames only. Diagnostics go to stderr. Unknown fields and protocol
minor-version behavior must be specified before implementation.

## Initial SDK Order

1. Go;
2. Node with TypeScript declarations;
3. Python;
4. Rust;
5. Java and C#;
6. PHP, Ruby, and Dart according to demand.

This sequence validates three common integration styles before multiplying the
maintenance surface. Publishing a directory is not publishing a supported SDK;
each language needs ecosystem-native packaging, tests, docs, provenance, and a
maintainer commitment.

## Consequences

- The core remains a Go-only contributor path; SDK toolchains are optional and
  independently testable.
- Users download a platform archive rather than one physically universal file.
- The release pipeline must build and test a matrix of
  SESAME/FYLO/CHEX/TTID sets.
- FYLO failure or incompatibility is a SESAME availability failure and must fail
  closed.
- Developers do not operate a second web server or expose a second application
  port for SESAME.
- The host application must correctly install framework adapters, TLS, rate
  limits, trusted-proxy handling, and route-level enforcement. Contract suites
  must test these integration responsibilities.
- The initial single-owner topology does not support several application
  replicas or unrelated applications sharing one FYLO root.
- Windows x64 can be previewed but cannot be production-supported while
  backup/restore parity is absent.
- Headless deployment is excellent for APIs and service-to-service use, but
  browser OIDC adopters must provide an approved interaction client.
- A stable error catalog and compatibility policy become first-class product
  work.
- Thin shims reduce drift but still create package-registry, language-version,
  documentation, and security-response obligations.

## Rejected Alternatives

- **One executable bitstream for every OS**: executable formats and system
  interfaces differ; this is not a realistic native distribution model.
- **Statically link the FYLO runtime into SESAME now**: FYLO and the engines it
  drives do not expose supported Go library/static linking contracts.
- **Embed and extract all FYLO binaries**: inflates every artifact, complicates
  signing and cleanup, and still requires platform selection. Reconsider only
  with a concrete one-file distribution requirement.
- **SDKs reimplement business rules**: creates inconsistent security behavior
  and multiplies patch latency.
- **Only generated SDKs**: generated clients are useful for models, but local
  subprocess lifecycle, cancellation, error mapping, and idiomatic APIs require
  a small reviewed hand-written layer.
- **Direct browser management SDK**: increases credential, CORS, CSRF, and token
  exposure. Use a server-side SDK/BFF.
- **Mandatory standalone SESAME HTTP daemon**: duplicates the developer's web
  server, adds another port and TLS boundary, and complicates local deployment.
  Retain it only as a possible future optional adapter for deployments that
  explicitly need a shared sidecar or service.

## Acceptance Gate

This ADR becomes Accepted when:

- NDJSON v1 defines versioning, errors, idempotency, pagination, limits,
  cancellation, and deprecation;
- a standards-dispatch RFC defines the bounded request/response fields,
  trusted-proxy rules, header and cookie handling, body limits, and framework
  adapter obligations before OAuth/OIDC endpoints are implemented;
- a Go proving client and host-framework adapter pass the shared black-box
  corpus against a real binary;
- one native release archive verifies its SESAME/FYLO/CHEX/TTID manifest and
  passes crash, restore, and upgrade tests;
- an interaction-contract threat model proves that an external renderer cannot
  advance or substitute authentication state;
- the project publishes platform and SDK support definitions.
