// Package saml verifies inbound SAML 2.0 assertions.
//
// This is the highest-risk code in SESAME and should be reviewed as such. It
// implements Exclusive XML Canonicalization and XML Signature verification
// in-tree, over `encoding/xml`'s raw token stream, for the reasons in
// docs/adr/0005-saml-signature-verification.md.
//
// The design principle running through all of it: **verify, then read only
// what was verified.** Verification returns the byte range of the signed
// element, and the caller parses that range alone. It never re-queries the
// document. XML Signature Wrapping — where an attacker relocates the signed
// element and puts a forgery where the reader looks — is the failure mode
// that has broken most SAML implementations, and it is defeated here by
// leaving the reader nowhere else to look.
//
// # Validation
//
// The canonicalizer is checked against libxml2's `xmllint --exc-c14n`, an
// independent implementation of the same specification, over nineteen cases
// covering attribute ordering, namespace scoping and rebinding, unused-prefix
// elimination, escaping, empty-element expansion, and the element shapes a
// real assertion carries. That comparison exists because this package cannot
// validate itself: a signer built on this canonicalizer would agree with it
// whether or not it is correct.
//
// The differential test skips when xmllint is absent rather than passing
// quietly, so a machine without it reports "not validated".
//
// Verification is also proven end to end against a signature this package did
// not help produce: the test signer canonicalizes with xmllint and only then
// signs, so a one-byte disagreement would fail the signature. Tampering with
// the subject, validity window, audience, or recipient of that signed
// assertion is caught by the digest.
//
// # Interoperability
//
// A pinned Keycloak 26.0 suite proves the full flow against one real identity
// provider. Other providers vary element ordering, namespace placement, and
// extensions, so each remains unproven until its own interoperability evidence
// exists. See the Phase 6 status in docs/PROJECT_PLAN.md.
package saml

import (
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// MaxDocumentBytes bounds a SAML message. Real assertions are a few kilobytes;
// anything near this is an attempt to make parsing expensive.
const MaxDocumentBytes = 512 * 1024

// maxDepth bounds element nesting. Deep nesting is the shape a parser-stack
// exhaustion attempt takes once entity expansion is unavailable.
const maxDepth = 100

var (
	// ErrDocumentTooLarge is returned when a message exceeds the bound.
	ErrDocumentTooLarge = errors.New("the SAML document exceeds the maximum size")
	// ErrDoctype reports a DOCTYPE directive. Go's parser will not expand
	// entities, but a document carrying a DTD at all is not one a provider
	// should be sending, and refusing it removes the question.
	ErrDoctype = errors.New("the SAML document carries a DOCTYPE, which is refused")
	// ErrAmbiguous reports a document that does not say unambiguously which
	// element counts. Every published wrapping attack depends on ambiguity.
	ErrAmbiguous = errors.New("the SAML document is ambiguous about which element is signed")
)

// element is one located element: its identifier, its depth, and the byte
// range it occupies in the original document.
type element struct {
	Name  xml.Name
	ID    string
	Start int
	End   int
	Depth int
}

// namespaceBinding is one prefix-to-URI mapping in scope.
type namespaceBinding struct {
	Prefix string
	URI    string
}

// canonicalize renders one element subtree in Exclusive XML Canonical form.
//
// Exclusive C14N differs from inclusive in what it does with namespaces: only
// those *visibly used* by an element — its own prefix and its attributes'
// prefixes — are emitted, so a subtree signed in one document verifies after
// being embedded in another. That property is why SAML uses it, and getting
// the "visibly used" rule wrong is how a canonicalizer silently produces
// output that verifies against the wrong bytes.
func canonicalize(
	document []byte,
	region element,
	withComments bool,
	inherited map[string]string,
) ([]byte, error) {
	return canonicalizeBytes(document[region.Start:region.End], withComments, inherited)
}

// canonicalizeBytes is the walk itself, over an already-extracted subtree.
//
// inherited carries the namespace bindings declared outside this subtree. An
// element that uses a prefix its ancestors declared would otherwise fail to
// resolve, and exclusive canonicalization requires that such a binding be
// rendered here — it is visibly used and no longer in scope.
func canonicalizeBytes(
	subtree []byte,
	withComments bool,
	inherited map[string]string,
) ([]byte, error) {
	decoder := xml.NewDecoder(strings.NewReader(string(subtree)))
	var out strings.Builder
	// scope is a stack of namespace bindings; rendered tracks what each depth
	// has already emitted, so a binding is not repeated on a descendant.
	scope := [][]namespaceBinding{inheritedBindings(inherited)}
	var rendered []map[string]string
	depth := 0

	for {
		token, err := decoder.RawToken()
		if err != nil {
			break
		}
		switch typed := token.(type) {
		case xml.StartElement:
			depth++
			if depth > maxDepth {
				return nil, fmt.Errorf("the SAML document nests deeper than %d elements", maxDepth)
			}
			scope = append(scope, declarationsOf(typed))
			inherited := inheritedRendering(rendered)
			emitted, err := writeStart(&out, typed, scope, inherited)
			if err != nil {
				return nil, err
			}
			rendered = append(rendered, emitted)
		case xml.EndElement:
			out.WriteString("</")
			out.WriteString(qualify(typed.Name))
			out.WriteString(">")
			depth--
			if len(scope) > 1 {
				scope = scope[:len(scope)-1]
			}
			if len(rendered) > 0 {
				rendered = rendered[:len(rendered)-1]
			}
		case xml.CharData:
			out.WriteString(escapeText(string(typed)))
		case xml.Comment:
			if withComments {
				out.WriteString("<!--")
				out.WriteString(string(typed))
				out.WriteString("-->")
			}
		case xml.ProcInst:
			// Processing instructions inside a signed subtree are legal and
			// canonicalized; SESAME refuses them rather than reproducing a
			// rule nothing sends.
			return nil, fmt.Errorf("%w: a processing instruction inside the signed element",
				ErrAmbiguous)
		case xml.Directive:
			return nil, ErrDoctype
		}
	}
	return []byte(out.String()), nil
}

// declarationsOf extracts the xmlns declarations an element carries.
func declarationsOf(start xml.StartElement) []namespaceBinding {
	var declared []namespaceBinding
	for _, attribute := range start.Attr {
		if attribute.Name.Space == "xmlns" {
			declared = append(declared, namespaceBinding{
				Prefix: attribute.Name.Local, URI: attribute.Value,
			})
			continue
		}
		if attribute.Name.Space == "" && attribute.Name.Local == "xmlns" {
			declared = append(declared, namespaceBinding{Prefix: "", URI: attribute.Value})
		}
	}
	return declared
}

// inheritedRendering flattens what ancestors have already emitted.
func inheritedRendering(rendered []map[string]string) map[string]string {
	inherited := map[string]string{}
	for _, level := range rendered {
		for prefix, uri := range level {
			inherited[prefix] = uri
		}
	}
	return inherited
}

// writeStart emits one start tag in canonical form and reports the namespace
// bindings it rendered.
//
// Canonical order is fixed: namespace declarations sorted by prefix, then
// attributes sorted by namespace URI then local name. Emitting them in
// document order instead would produce a different digest for the same
// document, which reads as a signature failure nobody can diagnose.
func writeStart(
	out *strings.Builder,
	start xml.StartElement,
	scope [][]namespaceBinding,
	inherited map[string]string,
) (map[string]string, error) {
	out.WriteString("<")
	out.WriteString(qualify(start.Name))

	used := visiblyUsedPrefixes(start)
	emitted := map[string]string{}
	for _, prefix := range sortedKeys(used) {
		uri, bound := resolvePrefix(scope, prefix)
		if !bound {
			// An unprefixed name with no default declaration is in the null
			// namespace, which is legitimate and renders nothing. A *named*
			// prefix with no binding is malformed XML.
			if prefix == "" {
				continue
			}
			return nil, fmt.Errorf("%w: prefix %q is not bound", ErrAmbiguous, prefix)
		}
		// Exclusive C14N omits a declaration an ancestor already rendered
		// with the same value; re-emitting it would change the digest.
		if inherited[prefix] == uri {
			continue
		}
		writeNamespace(out, prefix, uri)
		emitted[prefix] = uri
	}

	for _, attribute := range canonicalAttributes(start) {
		out.WriteString(" ")
		out.WriteString(qualify(attribute.Name))
		out.WriteString(`="`)
		out.WriteString(escapeAttribute(attribute.Value))
		out.WriteString(`"`)
	}
	out.WriteString(">")
	return emitted, nil
}

func writeNamespace(out *strings.Builder, prefix, uri string) {
	if prefix == "" {
		out.WriteString(` xmlns="`)
	} else {
		out.WriteString(` xmlns:`)
		out.WriteString(prefix)
		out.WriteString(`="`)
	}
	out.WriteString(escapeAttribute(uri))
	out.WriteString(`"`)
}

// visiblyUsedPrefixes is the exclusive-C14N rule: an element renders only the
// namespaces its own name and its attributes' names actually use.
func visiblyUsedPrefixes(start xml.StartElement) map[string]struct{} {
	used := map[string]struct{}{start.Name.Space: {}}
	for _, attribute := range start.Attr {
		if attribute.Name.Space == "xmlns" || attribute.Name.Local == "xmlns" {
			continue
		}
		// An unprefixed attribute is in no namespace and renders nothing.
		if attribute.Name.Space != "" {
			used[attribute.Name.Space] = struct{}{}
		}
	}
	return used
}

// resolvePrefix walks the scope stack outward for the nearest binding.
func resolvePrefix(scope [][]namespaceBinding, prefix string) (string, bool) {
	for index := len(scope) - 1; index >= 0; index-- {
		for _, binding := range scope[index] {
			if binding.Prefix == prefix {
				return binding.URI, true
			}
		}
	}
	return "", false
}

// canonicalAttributes drops namespace declarations and sorts the rest.
func canonicalAttributes(start xml.StartElement) []xml.Attr {
	attributes := make([]xml.Attr, 0, len(start.Attr))
	for _, attribute := range start.Attr {
		if attribute.Name.Space == "xmlns" ||
			(attribute.Name.Space == "" && attribute.Name.Local == "xmlns") {
			continue
		}
		attributes = append(attributes, attribute)
	}
	sort.Slice(attributes, func(left, right int) bool {
		if attributes[left].Name.Space != attributes[right].Name.Space {
			return attributes[left].Name.Space < attributes[right].Name.Space
		}
		return attributes[left].Name.Local < attributes[right].Name.Local
	})
	return attributes
}

func qualify(name xml.Name) string {
	if name.Space == "" {
		return name.Local
	}
	return name.Space + ":" + name.Local
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// escapeText and escapeAttribute implement the canonical escaping rules,
// which differ from Go's XML writer: canonical form escapes a fixed set and
// leaves everything else alone, so using xml.EscapeText would produce a
// different digest.
func escapeText(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\r", "&#xD;",
	)
	return replacer.Replace(value)
}

func escapeAttribute(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		`"`, "&quot;",
		"\t", "&#x9;",
		"\n", "&#xA;",
		"\r", "&#xD;",
	)
	return replacer.Replace(value)
}

// canonicalizeExcluding renders the signed element with the Signature subtree
// removed, which is what the enveloped-signature transform specifies.
//
// The excision is done on bytes rather than during the walk. Removing a
// complete element subtree from a well-formed document leaves it well-formed,
// so the two remaining spans concatenate into valid XML — and doing it this
// way means the canonicalizer never has to know why an element is absent.
func canonicalizeExcluding(
	document []byte,
	region, excluded element,
	withComments bool,
	inherited map[string]string,
) ([]byte, error) {
	if excluded.Start < region.Start || excluded.End > region.End {
		// A signature outside the element it covers is not enveloped, and
		// excising nothing would digest bytes the signer never saw.
		return nil, fmt.Errorf("%w: the signature is not inside the element it references",
			ErrAmbiguous)
	}
	subtree := make([]byte, 0, region.End-region.Start)
	subtree = append(subtree, document[region.Start:excluded.Start]...)
	subtree = append(subtree, document[excluded.End:region.End]...)
	return canonicalizeBytes(subtree, withComments, inherited)
}

// inheritedBindings renders an inherited scope map as a binding level.
func inheritedBindings(inherited map[string]string) []namespaceBinding {
	bindings := make([]namespaceBinding, 0, len(inherited))
	for prefix, uri := range inherited {
		bindings = append(bindings, namespaceBinding{Prefix: prefix, URI: uri})
	}
	sort.Slice(bindings, func(left, right int) bool {
		return bindings[left].Prefix < bindings[right].Prefix
	})
	return bindings
}
