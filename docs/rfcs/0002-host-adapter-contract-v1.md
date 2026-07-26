# RFC 0002: Framework-Neutral Host-Adapter Contract v1

- Status: Implemented
- Date: 2026-07-26

## Problem

SESAME is headless and opens no application port. A developer's existing
server must expose OAuth and OpenID Connect routes. The first Go host example
parsed every request, selected SDK methods, mapped machine errors to OAuth
errors, and constructed response headers itself. Repeating that implementation
for SvelteKit, Next.js, Nuxt, Solid, and every later framework would duplicate
security-sensitive protocol behavior and let adapters drift.

The contract must preserve the architectural boundary:

- the host owns listeners, TLS, routing, middleware, public limits, trusted
  proxy configuration, cookies, and rendered interactions;
- SESAME owns protocol validation, client authentication, error
  indistinguishability, redirects, replay resistance, and authorization state;
- SDKs own process lifecycle and typed transport only.

## Decision

Add `standards.dispatch` to machine protocol v1. Its payload carries a separate
`contract_version` so an SDK and engine can negotiate the public-route contract
independently of the NDJSON framing protocol.

Host adapters translate their request object into a closed envelope:

- one enumerated endpoint and uppercase method;
- duplicate-preserving query and form multimaps;
- the complete Authorization and DPoP fields, and no arbitrary header bag;
- the public absolute URI actually served when DPoP is present;
- host-owned route paths only for discovery.

The engine returns either bounded HTTP instructions or an `interaction`
action. It never returns templates, framework objects, middleware callbacks,
or listener configuration.

Version 1 covers discovery, JWKS, authorization, token, introspection,
revocation, and RP-initiated logout. Login and consent remain host-owned
interactions driven by existing authentication, consent, and
`oidc.interaction_*` operations.

## Security Properties

- Duplicate OAuth parameters are visible and rejected. A framework cannot
  silently collapse an attacker-controlled second value.
- Invalid authorization requests are rendered locally with no redirect. A
  redirect is returned only after SESAME validates it against client
  registration.
- Basic client authentication is parsed once in the engine. Using a posted
  client secret and HTTP Basic together is rejected.
- Public errors contain only OAuth error codes. Machine messages and secrets
  never become `error_description`.
- Token, introspection, revocation, logout, authorization, and error responses
  carry `no-store`; token responses also carry `Pragma: no-cache`.
- Response headers come from a seven-name allowlist. Adapters reject unknown
  names, CR/LF, unsupported response versions, and invalid status codes.
- Request names, values, value counts, and aggregate size are bounded before
  protocol dispatch.
- The DPoP URI is explicitly host-reported because the engine cannot observe
  HTTP. The engine still requires it to belong to the configured issuer
  origin.
- Interaction secrets remain bearer-equivalent and are never placed in a URL
  or exposed to browser JavaScript by the contract.

## Compatibility

Adding an optional request field, response header, endpoint, or action kind
requires a contract review. An adapter must fail closed on an action kind,
header, or contract version it does not understand.

Removing or changing a field, endpoint, error mapping, or semantic invariant
requires a new contract version. Machine protocol compatibility does not imply
host-adapter compatibility.

All SDKs expose one typed standards-dispatch method. Framework packages remain
thin wrappers over that method and must pass the shared fixtures and negative
corpus against a real SESAME executable.

## Consequences

The Go host example no longer implements OAuth parameter or error semantics.
Framework implementations still need small request/response translators and
their own secure interaction storage, rendering, CSRF controls, rate limits,
and trusted-proxy policy.

SvelteKit, Next.js, Nuxt, and Solid do not need framework changes for SESAME.
Each integration is ordinary application code built on the framework's public
request and response APIs. A framework-specific adapter is supportable only
after its native runtime tests exercise this contract against a real SESAME
binary.

The normative wire contract is
[`api/standards/v1`](../../api/standards/v1/README.md).
