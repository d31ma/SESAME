# ADR 0005: SAML Signature Verification Without a New Dependency

- Status: Accepted
- Date: 2026-07-25
- Accepted: 2026-07-26

## Context

Phase 6 slice 3 is inbound SAML 2.0: an identity provider posts a signed
assertion and SESAME turns it into a session. The security of that flow rests
entirely on verifying an XML Signature, which is a materially harder surface
than the JWT verification slice 1 needed.

Three things make it harder.

**Canonicalization.** A JWT signs a byte string that arrives verbatim. XML
signs a *canonical form* computed from a subtree, so verification requires
implementing Exclusive XML Canonicalization: namespace scoping, prefix
rewriting, attribute ordering, and byte-exact reserialisation.

**XML Signature Wrapping.** An attacker moves the signed element elsewhere in
the document and puts forged content where the reader looks. The signature
still verifies — over the original element — while the application reads the
forgery. This class has broken Shibboleth, OneLogin, python-saml, and
ruby-saml, among others. It is not a parsing bug; it is a bug in *which
element the application reads after verifying*.

**Entity expansion.** DTD entity references allow both denial of service
(billion laughs) and file disclosure (XXE).

`TestEngineDependencySurfaceStaysSmall` pins SESAME to one external module,
`golang.org/x/crypto`, and its comment states that a second "should be a
deliberate decision with an ADR, not something that arrives with a convenient
import". Go's standard library has no XML Signature or canonicalization
support, so SAML forces that decision.

## Investigation

Two properties of `encoding/xml` were measured before deciding, because the
decision turns on them.

**`RawToken()` preserves namespace prefixes.** `Token()` resolves prefixes to
URIs and discards which prefix was written, which would make byte-exact
canonical output impossible. `RawToken()` does not resolve: for
`<saml:Assertion xmlns:saml="…">` it reports `Name.Space == "saml"`, the
prefix as written. Exclusive canonicalization is therefore implementable over
the raw token stream, tracking namespace scope directly.

**`encoding/xml` refuses custom entity references.** Given
`<!DOCTYPE r [<!ENTITY a "AAAA">]><r>&a;</r>` the decoder surfaces the DOCTYPE
as an `xml.Directive` and then fails with `invalid character entity &a;`. It
does not expand entities and has no mechanism to fetch external ones. The
billion-laughs and XXE classes are closed by the parser, not by SESAME.

Also measured, and the reason a naive approach fails: `xml.Marshal` does not
round-trip. Given the assertion above it emitted
`<Assertion xmlns="…" ID="a1">`, rewriting the prefix and dropping two
attributes. Canonical output must be produced from the token stream, never by
reserialising a decoded struct.

## Decision

1. **No new dependency.** SESAME implements Exclusive XML Canonicalization and
   XML Signature verification in-tree, over `encoding/xml`'s raw token stream.
   The dependency surface stays at `golang.org/x/crypto`.

2. **Verify, then read only what was verified.** The verifier returns the
   *byte range of the signed element*, and the SAML domain parses its subject,
   conditions, and attributes from that range alone. It never re-queries the
   document for an `Assertion`. This makes XML Signature Wrapping structurally
   impossible rather than filtered: there is no second place to read from.

3. **Refuse ambiguity rather than resolving it.** A document carrying more
   than one `Assertion`, more than one `Signature`, a `DOCTYPE` directive, or
   a `Reference` URI that does not resolve to exactly one element is rejected
   outright. Every historical wrapping attack depends on a document that is
   ambiguous about which element counts, so ambiguity is the thing to refuse.

4. **A closed algorithm allowlist**, as slice 1 established: RSA-SHA256/384/512
   and ECDSA-SHA256/384/512 for signatures, SHA-256/384/512 for digests. No
   SHA-1, no HMAC — an HMAC signature method would let anyone holding the
   published certificate mint assertions.

5. **Exclusive canonicalization only.** `xml-exc-c14n#` and
   `xml-exc-c14n#WithComments` are supported; inclusive C14N is refused.
   Supporting one algorithm well beats supporting two adequately, and every
   current identity provider emits exclusive.

6. **The host owns the bindings.** HTTP-Redirect and HTTP-POST are HTTP
   concerns, so the host receives them and passes the decoded SAML message to
   the engine — the same boundary ADR 0003 sets and ADR 0004 applies to
   federation egress.

## Consequences

Positive:

- The supply chain is unchanged, and the architecture test that pins it keeps
  passing without an exception.
- Wrapping is addressed by construction. A verifier that returns bytes rather
  than a document leaves the caller nothing to be confused by.
- Every failure mode is testable without a network or a live identity
  provider: the attacks are documents.

Negative:

- SESAME carries its own canonicalization implementation, which is the most
  error-prone part of SAML. This is mitigated by keeping the supported surface
  narrow, by the verify-then-read-bytes design, and by an adversarial corpus
  built from the published wrapping techniques — but it remains the highest
  risk code in the project, and it should be reviewed as such.
- Inclusive canonicalization and SHA-1 are refused, so an identity provider
  configured for either will not interoperate until it is reconfigured. This
  is stated in the operator documentation rather than worked around.

## Alternatives considered

**Add an XML DSig library.** Rejected as the default: it would double the
external dependency surface for one slice, and the mature Go options carry
their own transitive graphs. The investigation showed the stdlib is sufficient,
which removes the argument for it. Worth revisiting only if the in-tree
canonicalizer proves unable to interoperate with real providers.

**Skip SAML.** Rejected: the roadmap lists it, and it is the protocol
enterprise deployments most often require. Deferring it because it is hard is
the wrong reason.

**Accept unsigned assertions when the response is signed, or vice versa,
without checking which.** Rejected explicitly because it is the shape of
several published bypasses. SESAME requires that the element it reads is the
element that was signed, and will not infer that from the presence of a
signature elsewhere.
