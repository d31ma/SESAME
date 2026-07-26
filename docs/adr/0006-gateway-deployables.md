# ADR 0006: LDAP and Proxy Gateways as Separate Deployables

- Status: Accepted
- Date: 2026-07-26
- Accepted: 2026-07-26

## Context

Phase 6 slice 4 is "LDAP and proxy gateways as separately deployed agents".
Two capabilities sit behind that sentence, and they are less alike than the
shared slice suggests.

An **LDAP gateway** lets software that only speaks LDAP authenticate against
SESAME. The population is real and not going away: VPN concentrators, network
appliances, backup software, older Linux hosts wired to `nss_ldap`, and
in-house services written against a directory that is being retired. Such a
gateway listens on 389 or 636, speaks a binary protocol, and answers Bind and
Search operations by consulting SESAME.

A **proxy gateway** — what authentik calls a proxy provider and what most
deployments know as a forward-auth or identity-aware proxy — puts
authentication in front of an application that has none. It terminates the user
agent's request, runs an OIDC flow, sets a session cookie, and either forwards
the request upstream or answers a reverse proxy's subrequest with an allow or a
deny plus identity headers.

Both need a network listener. ADR 0003 made the engine headless: the host
application owns every listener, TLS boundary, route, and middleware chain, and
`TestEngineOpensNoNetworkListener` fails the build if `net/http` appears in
`go list -deps ./cmd/sesame`. ADR 0004 kept that intact for federation by
having the engine *direct* fetches the host performs.

That trick does not transfer. Federation egress is request/response initiated
by the engine's own flow, so it can be decomposed into instructions. A gateway
is the opposite shape: it is a *server*, driven by traffic that arrives from
outside on a schedule nobody controls, and there is no host application in the
picture to own the listener. A VPN appliance binding to an LDAP port is not
going to embed a Go SDK.

There is a second problem that has nothing to do with listeners. **LDAP Simple
Bind carries the password in the clear to whatever accepts it**, so an LDAP
gateway is by construction a password-collecting endpoint. That is a shape
SESAME has otherwise avoided: the authentication surface takes a password only
inside a persisted transaction it created, and passkeys are the preferred
factor precisely because nothing types a reusable secret into an intermediary.
A gateway does not merely relay authentication; it becomes a party that sees
every password it relays, and MFA has no place to happen in a protocol whose
success signal is one bind result.

## Decision

1. **Gateways are separate deployables, not engine features.** Each is its own
   binary with its own version, its own release artifact, its own threat model
   section, and its own trust boundary. The engine keeps its no-listener
   property and its architecture test unchanged.

2. **A gateway is an SDK consumer, with no privileged path.** A gateway talks
   to SESAME exactly as any host application does — over the machine protocol
   through a language SDK, using operations that already exist and are already
   drift-checked. No gateway gets an operation that a normal host cannot call,
   and no gateway holds a credential that grants more than the flows it runs.
   If a gateway needs something the public surface cannot express, that is a
   gap in the public surface, and it gets fixed there.

3. **One SESAME subprocess still owns one FYLO root.** Until the Phase 7
   coordination work lands, a gateway cannot open its own engine against a root
   an application is already using. A gateway therefore either runs beside the
   owning application and reaches SESAME through it, or waits for coordination.
   This is a real constraint on deployment topology and is stated up front
   rather than discovered.

4. **The proxy gateway comes first, and it is forward-auth only.** It
   implements the subrequest shape (`auth_request` in nginx, `forward_auth` in
   Traefik and Caddy): a request arrives, the gateway answers allow or deny and
   attaches identity headers. It does not proxy the upstream body. That keeps
   it a decision surface rather than a data path, which is both the smaller
   security surface and the smaller thing to get right.

5. **Identity headers are stripped inbound and signed outbound.** Any header
   the gateway sets is removed from the incoming request first — an upstream
   that trusts `X-Forwarded-User` and a gateway that forwards a client-supplied
   one is a complete authentication bypass. The documented deployment requires
   that the upstream be reachable only through the gateway, because a header
   contract is only as good as the network that enforces it.

6. **The LDAP gateway is deferred, and its password handling gates it.** It is
   not built until: the password path is designed to be no weaker than the
   direct one (bind attempts subject to the same rate limits and lockouts,
   audited as originating from the gateway, and refused for any principal whose
   policy requires a second factor rather than silently downgraded); LDAPS or
   StartTLS is mandatory with no plaintext-389 mode outside an explicit
   development flag; and the search surface is an explicit projection with a
   per-tenant scope rather than a queryable directory. A gateway that lets an
   MFA-required principal authenticate with a password alone is a downgrade
   attack wearing a compatibility label, and shipping one would contradict the
   step-up work in Phase 4.

7. **A gateway's own credential is a first-class secret with its own
   identity.** Each gateway authenticates to SESAME as a registered client
   with a named tenant scope, so its actions are attributable in the audit
   ledger as the gateway's rather than as a generic operator's, and it can be
   disabled without touching anything else.

8. **Support is claimed per gateway, not for the slice.** Each needs native
   packaging, interoperability evidence against at least two real consumers
   (for the proxy: nginx `auth_request` and Traefik `forward_auth`; for LDAP:
   two named clients), adversarial tests, and operator documentation before it
   is described as supported anywhere.

## Consequences

Positive:

- The engine's structural claims survive slice 4 as they survived slice 1.
  Nothing about a gateway can weaken them, because a gateway is on the far
  side of the same public contract every host uses.
- The public operation surface is exercised by a demanding consumer. Anything
  a gateway cannot express is a gap worth closing for everyone.
- The two capabilities are decoupled. The proxy gateway can ship while the
  LDAP question is still open, instead of the slice being blocked on its
  hardest part.
- A gateway is separately versioned and separately disabled, so an incident in
  one does not implicate the engine or the other.

Negative:

- More artifacts to build, sign, package, and support per platform, and a
  second thing for an operator to configure and upgrade.
- The one-root constraint means a gateway cannot yet be deployed as an
  independent tier beside an application. Some topologies people will want are
  simply not available until Phase 7.
- Forward-auth only means the proxy gateway does not cover applications that
  cannot sit behind a reverse proxy, which is a real if uncommon gap.
- Deferring LDAP means SESAME cannot yet replace a directory for the appliance
  population, which is one of the concrete reasons people adopt authentik.
  This is a deliberate trade: no capability is worth introducing a documented
  MFA bypass.

## Alternatives considered

**Put the listeners in the engine, behind a configuration flag.** Rejected: it
deletes the architecture test the Phase 4 gate depends on, and it makes the
engine's attack surface depend on configuration rather than on structure. A
flag that turns a headless engine into a network server is not a headless
engine.

**Make the gateways host-application middleware instead of deployables.** This
works for the proxy shape and not at all for LDAP, and even for the proxy it
would require every host framework to grow an adapter. Rejected as a general
answer, but note that a host that wants forward-auth inside its own process can
already build it on the existing operations; the gateway exists for deployments
with no such host.

**Ship the LDAP gateway with a documented "password only" caveat.** Rejected.
The caveat would be true and would still be wrong: an operator who enables the
gateway for one legacy appliance has, in doing so, created a password-only path
to every principal in the tenant. The mitigation — refusing principals whose
policy requires a second factor — is not an optional refinement, it is the
feature.

**Have the gateway embed the engine rather than talk to it.** Rejected for the
same reason SESAME ships no embeddable engine at all: an on-device or
in-gateway copy of authoritative state can never be authoritative, and two
writers to one FYLO root is exactly what Phase 7 exists to make possible.
