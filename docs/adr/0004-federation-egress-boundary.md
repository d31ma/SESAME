# ADR 0004: Federation Egress Boundary

- Status: Accepted
- Date: 2026-07-25
- Accepted: 2026-07-26

## Context

Phase 6 begins with inbound OpenID Connect federation: a principal
authenticates at an external OpenID Provider and arrives at SESAME with an
authorization code. Completing that flow requires four outbound HTTP requests
to a server SESAME does not control:

1. the provider's discovery document, at `/.well-known/openid-configuration`;
2. the provider's JWKS, to obtain the key that signed the ID token;
3. the token endpoint, to exchange the authorization code;
4. optionally the UserInfo endpoint, for claims absent from the ID token.

SESAME links no HTTP package. `TestEngineOpensNoNetworkListener` fails the
build if `net/http` appears anywhere in `go list -deps ./cmd/sesame`, and its
comment is explicit that this covers "an HTTP server **or client**". That test
encodes ADR 0003's decision that the host application owns every network
boundary, and the Phase 4 exit gate cites it as mechanically checked evidence.

Federation is therefore the first feature that appears to require breaking a
load-bearing architectural claim. It does not, and the alternative is better on
its own merits.

Outbound federation traffic is also the largest new attack surface SESAME has
taken on. A provider URL is operator-supplied and a discovery document is
attacker-influenced whenever the provider is compromised or impersonated. The
risks are server-side request forgery against the host's internal network,
redirect chains to internal addresses, unbounded responses, hostile JSON, and
attacker-chosen signing keys.

## Decision

1. **The engine performs no network I/O for federation.** `net/http` stays out
   of the engine's dependency graph, and the architecture test keeps enforcing
   that.

2. **SESAME directs the fetch; the host performs it.** Every federation
   operation that needs remote data returns an explicit *fetch instruction*
   naming the exact URL, method, and required headers. The host or SDK
   executes it and returns the response body to SESAME in a following
   operation. SESAME never accepts a URL from the caller for this purpose: the
   instruction is derived from the registered provider's configuration, so a
   caller cannot redirect the engine's trust to a server of their choosing.

3. **Every fetched document is untrusted input, validated in the engine.**
   Discovery documents, JWKS, token responses, and ID tokens are parsed and
   checked inside SESAME under bounded sizes and an explicit schema. The host
   is a transport, never a validator. A compromised or lazy host can withhold
   or corrupt a response, and the flow then fails closed; it cannot cause
   SESAME to accept an assertion it would otherwise reject.

4. **The registered issuer is the trust anchor.** The discovery document's
   `issuer` must equal the registered issuer exactly. Every endpoint URL the
   document supplies must share that issuer's origin, must be `https`, and is
   re-derived rather than trusted verbatim. A discovery document cannot move
   the token endpoint to another host.

5. **Signature verification uses an explicit algorithm allowlist and pins the
   key by `kid`.** SESAME verifies external ID tokens with RS256, RS384,
   RS512, ES256, ES384, and ES512, which cover what real providers issue. It
   accepts no `alg` outside that list, refuses `none` and every MAC algorithm,
   and requires that the JWK selected by `kid` declares a matching key type.
   SESAME continues to *sign* only with ES256; verifying another party's
   choices is a different question from making its own.

6. **The host's fetch is constrained by documented operator requirements**, not
   by hope. `docs/FEDERATION.md` states that the host must resolve and connect
   only to public addresses, refuse redirects to private ranges, bound response
   size and time, and pin TLS verification on. SESAME cannot enforce these from
   the other side of a pipe, so it says so plainly rather than implying a
   protection it does not provide.

7. **A federated login transaction is persisted, single-use, and tenant-bound.**
   State, nonce, and PKCE verifier live in a FYLO document that survives
   restart, is consumed on first successful completion, and is scoped to one
   tenant and one provider.

## Consequences

Positive:

- The engine's dependency surface and the no-listener claim survive Phase 6
  intact, and both remain mechanically checked.
- No TLS stack, proxy configuration, certificate store, or connection pool
  enters the engine. The host already owns all of it for its own traffic, and
  operators configure egress in one place.
- SSRF is structurally reduced rather than filtered: the engine emits only URLs
  derived from a registered issuer's origin, so there is no caller-controlled
  URL for an attacker to aim.
- Federation is testable without a network. Every negative case — a hostile
  discovery document, a wrong `kid`, an `alg` downgrade, a replayed code —
  is exercised by handing the engine a crafted response body.

Negative:

- Federation takes more round trips between host and engine than an in-engine
  HTTP client would, and the host carries real responsibility for egress
  safety. This is documented as an operator requirement.
- SDKs gain an HTTP call they did not previously make. It stays a plain fetch
  of a URL the engine supplied, with no protocol semantics, so the rule that
  shims own transport and never security decisions still holds.
- SESAME cannot refresh a provider's JWKS on its own schedule; key rotation is
  driven by the host re-fetching when SESAME reports an unknown `kid`.

## Alternatives considered

**Link `net/http` and add an in-engine egress broker with an allowlist.** This
is what the roadmap's "egress broker" language suggested. Rejected: it deletes
the architecture test that the Phase 4 gate depends on, moves TLS and proxy
configuration into the engine, and replaces a structural guarantee with a
filter that has to be kept correct. It also makes every federation failure mode
untestable without a live server or an injected transport.

**A sidecar fetcher process spawned by the engine.** Rejected: it reintroduces
the same egress surface one process away, doubles the supervision problem, and
gives operators a second thing to configure for no gain over asking the host,
which already has a configured HTTP client.
