# Inbound SAML 2.0

SESAME can act as a SAML service provider to an external identity provider, so
a person authenticates at their own IdP and arrives with a SESAME session.

This is the *inbound* half only. SESAME does not act as a SAML identity
provider, does not produce metadata documents, and does not implement Single
Logout. Those are not supported, and no part of this document should be read
as claiming otherwise.

Like [inbound OIDC federation](FEDERATION.md), part of the security here is
not enforceable by SESAME and has to be carried out by whoever runs it. Those
obligations are in [The host's obligations](#the-hosts-obligations), and they
are not optional.

## The shape of it

SAML's browser bindings mean the host, not SESAME, moves every byte:

1. The host asks the engine to start a login. The engine returns a redirect
   URL, already DEFLATE-and-base64 encoded for the HTTP-Redirect binding, plus
   the raw `AuthnRequest` for a host that would rather POST it.
2. The host redirects the browser there.
3. The identity provider authenticates the person and posts a `SAMLResponse`
   back to the host's assertion consumer service.
4. The host hands that field to the engine verbatim. The engine decodes,
   parses, verifies, and issues a session.

The engine opens no socket: `net/http` is absent from its dependency graph and
`TestEngineOpensNoNetworkListener` fails the build if it appears. It never
fetches provider metadata either — an operator registers the certificate,
which is why there is no fetch instruction here as there is for OIDC.

The consequence worth understanding: **the host is a transport, never a
validator.** A host that corrupts or withholds a response causes the flow to
fail closed. It cannot cause SESAME to accept an assertion it would otherwise
reject. The host is not asked to parse XML, check a signature, or understand
SAML at all.

## Signature verification

Verification is the whole feature, and
[ADR 0005](adr/0005-saml-signature-verification.md) records how it is built
and why no XML signature library was added.

Three rules govern it:

**Verify, then read the verified bytes.** Nothing outside the element the
signature covers reaches the reader. `Verify` returns the signed subtree and
`ParseAssertion` takes only that, so it is not possible for a later change to
read an attribute from the surrounding document by accident.

**Refuse ambiguity rather than resolve it.** Every published XML Signature
Wrapping attack works by making a document readable two ways and relying on
the verifier and the reader disagreeing. SESAME never chooses. A document is
rejected unless it carries exactly one `Signature`, one `SignedInfo`, one
`Reference`, one `DigestValue`, one `SignatureValue`, and at most one
`Assertion`, and unless that reference resolves to exactly one element.

**A closed algorithm allowlist.** RSA and ECDSA with SHA-256, SHA-384, or
SHA-512. No SHA-1, no HMAC, no `Algorithm` a document can talk the engine
into. Exclusive canonicalization only; inclusive canonicalization is refused
rather than approximated. A DOCTYPE declaration is refused outright, which
closes entity expansion and external entities together.

What a valid signature still does not answer is checked separately: the
Issuer, the Audience, the Recipient, the `InResponseTo` binding to the request
SESAME actually sent, and the validity window with sixty seconds of clock
skew. An assertion with no `NotOnOrAfter`, no audience, or no `InResponseTo`
is refused — an assertion that never expires makes one capture permanent, and
an unsolicited one has no binding that makes a stolen one useless elsewhere.

Every assertion is single use. The claim is recorded in the completion event
and replays into the projection, so a restart cannot forget that an assertion
was already spent. `test/fylo/saml_test.go` proves this against a real FYLO
runtime.

## Setting up a provider

### 1. Register

```bash
sesame saml provider-register \
  --tenant-id tnt_... \
  --name "Corp SSO" \
  --entity-id https://login.example.com/metadata \
  --sso-url https://login.example.com/sso \
  --certificate ./idp-signing.pem \
  --identifier-namespace email \
  --linking verified_email
```

The **entity ID** is the trust anchor. It is compared byte for byte against
every assertion's `Issuer`, so SESAME refuses leading or trailing whitespace
rather than trimming it: trimming would make the engine accept an Issuer the
provider never sends. It is a URI, not necessarily a URL, so a `urn:` value is
accepted.

The **single sign-on URL** must be `https`. A browser carries the
`AuthnRequest` there and the assertion comes back through the browser too, so
plaintext would expose the whole flow. There is no loopback exception, because
the provider is remote.

`--certificate` takes a path, not the certificate itself: PEM on a command
line is unreadable and easy to mangle. Bare base64 as copied out of a metadata
document is accepted too.

**Rotation.** Pass `--certificate` more than once to register several. This is
the normal case: a provider publishes its new certificate before it starts
signing with it, and SESAME must accept either until the old one is withdrawn.
The limit is eight.

`--identifier-namespace` names the SESAME namespace a `NameID` claims. SAML
does not require a `NameID` to be an email address, so this is explicit rather
than assumed.

### 2. Choose a linking policy

`--linking strict` (the default) requires an existing link. A verified
assertion for an unknown subject is refused with `saml_subject_not_linked`. Use
this when accounts are created by an administrator or by
[SCIM provisioning](PROVISIONING.md), and a federated login should only ever
attach to one that already exists.

`--linking verified_email` matches the `NameID` against the tenant's
identifiers and provisions a principal if none matches.

> **Understand what `verified_email` means here.** Unlike OpenID Connect,
> SAML has no `email_verified` claim to consult. There is nothing to check:
> the provider asserting a `NameID` *is* the assertion. That makes the choice
> of provider the whole trust decision, which is why this is opt-in per
> provider rather than the default. Enable it only for a provider you trust to
> assert addresses in a namespace you control.

### 3. Drive a login

```bash
sesame saml login-start \
  --tenant-id tnt_... \
  --provider-id sam_... \
  --consumer-url https://app.example.com/saml/acs
```

This returns `redirect_url` (send the browser there), `authn_request` (the raw
XML, if you would rather POST it), `login_id`, `request_id`, and `expires_at`.
The login lasts fifteen minutes — long enough for a person to authenticate
including an MFA prompt, short enough that an abandoned transaction is not a
standing replay target.

The `RelayState` on the redirect URL is the login ID, so the host knows which
transaction a response answers. It is a handle, not a secret: completing a
login still requires a valid assertion.

Then, with the `SAMLResponse` form field the provider posted:

```bash
sesame saml login-complete \
  --tenant-id tnt_... \
  --login-id sal_... \
  --assertion ./response.b64
```

The session that comes back has assurance `federated`, for the same reason an
inbound OIDC session does: SESAME did not witness the credential. A step-up
policy requiring `mfa` is not satisfied by a federated login, however the
provider authenticated the person.

### 4. Disable when the relationship ends

```bash
sesame saml provider-disable --tenant-id tnt_... --provider-id sam_... \
  --reason "contract ended"
```

Disablement is durable and immediate. It stops new logins and refuses
in-flight ones on the next request, not the next restart. Running it twice is
a no-op rather than an error, so an operator retrying after a timeout is not
told the second attempt failed.

## What the caller is told, and what the ledger records

Every rejected assertion returns one code, `saml_assertion_rejected`,
regardless of why. A caller who can tell a bad signature from a wrong audience
from an expired window learns the shape of the flow, so the caller is told
nothing.

The specific reason goes to the audit ledger on a `saml.login_failed` event as
a stable code: `ambiguous_document`, `unsigned`, `tampered`,
`invalid_signature`, `unsupported_algorithm`, `expired`, `audience_mismatch`,
`request_mismatch`, `unusable_subject`, or `invalid_assertion`. That is where
an operator diagnosing a broken provider should look. The assertion itself is
never logged.

The other wire codes are `saml_provider_not_found` (which covers unknown,
disabled, and cross-tenant alike), `saml_login_not_found` (unknown, closed,
expired, and cross-tenant alike), and `saml_subject_not_linked`.

## The host's obligations

These are not enforceable by SESAME. A deployment that skips them is not
secure, however correct the engine is.

1. **Serve the assertion consumer service over TLS.** The `SAMLResponse` is a
   bearer credential in transit.
2. **Pass the `SAMLResponse` through unmodified.** Do not parse it, do not
   re-serialize it, do not pretty-print it. Canonicalization is byte-exact;
   an XML round-trip through most libraries will change bytes the signature
   covers and turn a valid assertion into a rejected one.
3. **Use the same `consumer_url` at `login-start` and at the endpoint that
   receives the response.** The engine checks the assertion's `Recipient`
   against the value the login was started with. A mismatch is a refusal.
4. **Bound the size of the form field you accept** before handing it over.
   The engine bounds the decoded document at 512 KiB, but a host that buffers
   an unbounded upload first has already paid the cost.
5. **Do not treat `RelayState` as authenticated.** It comes back through the
   browser. It names a transaction; it proves nothing.

## What is not supported

Stated plainly, because a gap read as a feature is worse than a gap:

- **SESAME as a SAML identity provider.** Inbound only.
- **SAML metadata.** Neither produced nor consumed. An operator registers the
  entity ID, SSO URL, and certificate explicitly.
- **Single Logout.** Revoking the SESAME session is a local operation; it does
  not propagate to the identity provider.
- **Encrypted assertions.** `EncryptedAssertion` is not decrypted. A provider
  that requires encryption cannot be used yet.
- **Signed `AuthnRequest`s.** SESAME does not sign the requests it sends. A
  signed request protects the *provider* from forged requests, not SESAME from
  forged assertions, and every assertion is verified on the way back
  regardless. A provider that requires signed requests cannot be used yet.
- **Attribute-driven group or role assignment.** Attributes are parsed and
  available on the verified assertion, but nothing consumes them yet. Use
  [SCIM](PROVISIONING.md) for group membership.
- **Broad identity-provider interoperability.** The full flow is proven against
  the pinned Keycloak 26.0 suite described below. Okta, Entra ID, Google
  Workspace, Shibboleth, ADFS, and every other provider remain unproven; test
  the full flow before relying on one of them.

## Interoperability evidence

`test/interop` runs SESAME against a real Keycloak (pinned to
`quay.io/keycloak/keycloak:26.0`) in Docker. It is opt-in:

```bash
SESAME_INTEROP=1 \
  SESAME_FYLO_ALLOW_DEVELOPMENT=1 SESAME_FYLO_BUILD_TARGET=macos-arm64 \
  FYLO_BINARY=/absolute/path/to/fylo \
  go test -count=1 -timeout 20m ./test/interop
```

The suite brings up the container, creates a realm, registers SESAME as a SAML
client under its own entity ID, creates a user, reads the provider's published
metadata, and then drives the browser half of the flow: it follows the redirect,
submits the login form, and takes the `SAMLResponse` Keycloak hands back. Set
`SESAME_INTEROP_KEEP=1` to leave the container up between runs.

Four claims are covered: a login interoperates end to end, a real assertion is
single-use, another tenant cannot complete a login it did not start, and an
edited assertion is refused.

### What it found

The first run failed, and the reason is worth recording because it is the exact
failure mode an adversarial suite cannot catch.

Verification passed. Exclusive canonicalization, the SHA-256 digest, and the
RSA-SHA256 signature all reproduced correctly over a document Keycloak wrote.
**Parsing** then failed with `expected element <Assertion> in name space ... but
have saml`.

Keycloak writes `<saml:Assertion>` and binds the `saml` prefix once, on the
enclosing `<samlp:Response>`. The signed byte range therefore uses a prefix that
nothing inside it declares, and handing that range to an XML decoder on its own
resolves `saml` to the literal string `saml`. Every fixture in
`internal/domain/saml/samltest` declared the prefix on the assertion element
itself, which made the extracted subtree a standalone document by accident — so
the whole suite agreed with the bug.

The canonicalizer had the inherited bindings all along; `Signed` simply never
carried them to the parser. It does now, and
`samltest.Signer.SignInherited` produces the real shape so the regression is
caught without Docker.

### Still unproven

Keycloak is one provider. Okta, Entra ID, Google Workspace, Shibboleth, and
ADFS each have their own XML habits, and this suite says nothing about them.
Treat any provider not listed here as unproven.
