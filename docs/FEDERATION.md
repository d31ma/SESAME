# Inbound OIDC federation

SESAME can act as a relying party to an external OpenID Provider, so a person
authenticates at their own identity provider and arrives with a SESAME
session.

This document is written for the operator and the host application, because
part of the security of this feature is not enforceable by SESAME and has to
be carried out by whoever runs it. Those obligations are in
[The host's obligations](#the-hosts-obligations), and they are not optional.

## The shape of it: SESAME names, the host fetches

Federation needs four requests to a server SESAME does not control — discovery,
JWKS, the token exchange, and optionally UserInfo. **SESAME makes none of
them.** `net/http` is absent from the engine's dependency graph and
`TestEngineOpensNoNetworkListener` fails the build if it appears.

Instead the engine returns a *fetch instruction* naming the exact URL and
method, the host performs it, and the response comes back as bytes that the
engine parses and validates. [ADR 0004](adr/0004-federation-egress-boundary.md)
records why.

The consequence worth understanding: **the host is a transport, never a
validator.** A host that returns a corrupted or withheld response causes the
flow to fail closed. It cannot cause SESAME to accept an assertion it would
otherwise reject.

The URL in every instruction is derived from the registered issuer, never from
a caller. There is no caller-controlled address, which is why server-side
request forgery is structurally absent here rather than filtered.

## Setting up a provider

### 1. Register

The provider's client secret is read from the environment, not a flag, so it
does not land in shell history or a process listing:

```bash
export SESAME_PROVIDER_CLIENT_SECRET=<the provider's secret>
sesame federation provider-register \
  --tenant-id tnt_... \
  --name "Corp SSO" \
  --issuer https://login.example.com \
  --client-id <what the provider knows SESAME as> \
  --scopes email \
  --linking verified_email \
  --email-claim email
```

The issuer is the trust anchor for everything that follows. It must be `https`,
carry no query, fragment, or userinfo, and **must not end in a trailing
slash** — OpenID Connect compares `iss` byte for byte, so the stored value has
to be exactly what the provider will send. SESAME refuses a trailing slash
rather than trimming one, because trimming would make it accept an issuer the
provider never sends.

Registration returns the discovery URL to fetch.

### 2. Configure

Fetch that URL and the `jwks_uri` it names, then hand both documents back:

```bash
sesame federation provider-configure \
  --tenant-id tnt_... --provider-id idp_... \
  --discovery ./openid-configuration.json \
  --key-set ./jwks.json
```

SESAME validates both as adversarial input:

- the document's `issuer` must equal the registered issuer exactly;
- every endpoint it names must sit on that issuer's origin, over `https`;
- the key set is bounded in size and count, and must not declare a duplicate
  `kid`.

A discovery document therefore cannot move the token endpoint — which receives
SESAME's client secret — or the JWKS URI — which decides what key verifies an
assertion — to a server the operator never registered.

**Validated metadata is not snapshotted.** After a restart a provider comes
back registered but unconfigured, and must be configured again. This is
deliberate: metadata and keys are refetchable, and a stale copy restored from a
snapshot could pin SESAME to a key the provider has already rotated away.
Treat re-configuration as part of starting the host.

### Linking policy

`--linking strict` (the default) means an administrator must link an external
subject to a principal before any federated login succeeds. A valid assertion
for an unknown subject is refused.

`--linking verified_email` matches on an email claim and provisions a new
principal when none matches. It requires `--email-claim`, and it requires the
provider to assert `email_verified: true`. **An absent or false flag is
refused.** An unverified email is a string the user typed at the provider;
honouring it would let anyone who can register there claim an existing account.

## Completing a login

1. `federation.login_start` returns the authorization URL. Send the browser
   there. State, nonce, and a mandatory S256 PKCE challenge are generated and
   stored by the engine; the verifier never leaves it.
2. On callback, `federation.login_exchange` checks the returned state and
   returns the token request to perform.
3. `federation.login_complete` takes the resulting ID token and issues a
   session.

A federated login transaction is single-use, tenant-bound, and expires after
15 minutes. Its secrets are dropped the moment it is no longer pending.

### What is checked on the ID token

Signature first, then every claim. Nothing in the body is trusted before the
signature verifies.

- **Algorithm allowlist**: RS256, RS384, RS512, ES256, ES384, ES512. `none`
  and every MAC algorithm are absent, so an attacker cannot downgrade into a
  mode where the published verification key becomes the signing secret.
- **Key pinned by `kid`.** With no `kid`, SESAME proceeds only if the provider
  publishes exactly one key of that type — it will not try keys until one
  works.
- RSA moduli below 2048 bits are refused; EC keys must be points on their
  declared curve.
- `iss` exact, `aud` contains this client, and where there are several
  audiences `azp` must be this client.
- `exp`, `iat`, `nbf` with 60 seconds of skew.
- `nonce` must match this login. This is what stops a token captured from
  another session at the same provider being replayed here.

SESAME continues to **sign** only with ES256. Verifying what another party
chose is a separate question from choosing its own.

### Every rejection looks the same

Whatever fails, the caller gets `assertion_rejected`. A caller who can tell
"wrong nonce" from "unknown key" from "bad signature" can map the flow. The
specific reason — `unknown_key`, `expired`, `nonce_mismatch`,
`invalid_assertion` — goes to the audit ledger, where an operator can read it.

If you are diagnosing a broken provider, read the ledger, not the API response.

### Assurance

A federated session carries `federated` assurance, deliberately distinct from
`password`. SESAME did not witness the credential; it trusted a third party's
statement about one. A federated session therefore does **not** satisfy a
step-up requirement that a locally proven factor would. If you want federation
to satisfy such a requirement, that is a policy decision to make explicitly.

## The host's obligations

SESAME cannot enforce any of this from the far side of a pipe. These are stated
rather than implied, because a protection nobody implements is worse than one
nobody claimed.

**Egress safety.** The host performs the fetches, so the host owns SSRF
defence:

- resolve and connect only to public addresses; refuse RFC 1918, loopback,
  link-local (including `169.254.169.254`), and IPv6 unique-local targets;
- re-check after every redirect, or refuse redirects entirely;
- bound response size and total time — SESAME refuses documents above 256 KiB,
  but only after the host has already read them;
- keep TLS certificate verification on.

SESAME validates that every URL it *emits* is on the registered issuer's
origin. It cannot see where DNS actually points, which is the gap the host
closes.

**Credential handling.** `federation.login_exchange` returns the provider's
client secret in the form body, because the host makes that call. That response
is credential material: do not log it, do not cache it, and do not pass it
anywhere but the provider's token endpoint.

**Deployment key.** The provider's client secret is sealed with the deployment
secrets key. Restoring a backup without that key leaves a provider that cannot
complete a token exchange.

## Auditing

Every federation action appends to the security ledger:

`federation.provider_registered`, `provider_updated`, `provider_disabled`,
`login_started`, `login_completed`, `login_failed`, `subject_linked`,
`subject_unlinked`.

External subjects are recorded as a salted hash bound to their provider, never
in the clear: the ledger is append-only, and it should not become a directory
of every federated user's identity at their provider.

## What is not implemented

Named so nobody infers them from the presence of the rest:

- **Outbound federation.** SESAME is the relying party here, not the provider,
  for external identities.
- **SAML and SCIM through this surface.** They are implemented as separate
  inbound-federation and provisioning contracts, not as modes of the OIDC
  federation operations described here.
- **LDAP.** The gateway is designed but deliberately deferred; no LDAP support
  is claimed.
- **UserInfo.** The endpoint is validated when a provider declares it, but
  SESAME reads claims only from the ID token today.
- **Automatic key rotation.** SESAME reports `unknown_key` when a provider
  signs with a key it does not hold; re-configuring with a fresh JWKS is the
  remedy, and it is the host's to drive.
- **Provider-initiated logout.** Ending the SESAME session does not end the
  session at the provider.
