package saml

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// located is everything Verify needs, resolved from one pass over the
// document with every ambiguity refused.
type located struct {
	Signature        element
	SignedInfo       element
	Signed           element
	SignatureMethod  string
	DigestMethod     string
	DigestValue      string
	SignatureValue   string
	C14NWithComments bool
	// Inherited are the namespace bindings in scope at the signed element,
	// which exclusive canonicalization needs and which are declared outside
	// the signed byte range.
	Inherited map[string]string
	// SignedInfoInherited is the same, for SignedInfo. It is a different
	// scope: SignedInfo sits inside Signature, which commonly declares the
	// dsig prefix, so canonicalizing it against the signed element's scope
	// would resolve against the wrong bindings.
	SignedInfoInherited map[string]string
}

// locate finds the single signature and the single element it covers.
//
// This function is where XML Signature Wrapping is defeated, and it does so by
// refusing rather than choosing. Every published wrapping attack works by
// making a document ambiguous — two assertions, two signatures, a reference
// matching several elements, an identifier that repeats — and then relying on
// the verifier and the reader disagreeing about which one counts. SESAME
// never picks. If the document does not name exactly one signature over
// exactly one element, it is rejected.
func locate(document []byte) (located, error) {
	scan := &scanner{}
	decoder := xml.NewDecoder(strings.NewReader(string(document)))
	for {
		start := decoder.InputOffset()
		token, err := decoder.RawToken()
		if err != nil {
			break
		}
		if err := scan.consume(token, start, decoder.InputOffset()); err != nil {
			return located{}, err
		}
	}
	return scan.resolve()
}

// scanner accumulates elements and signature parts in document order.
type scanner struct {
	depth int
	// open tracks elements whose end tag has not been seen.
	open []element
	// scopes mirrors open, holding each level's namespace declarations.
	scopes []map[string]string
	// withID is every element carrying an ID, which is what a Reference can
	// name. Duplicates are kept so resolve can refuse them.
	withID     []element
	signatures []element
	signedInfo []element
	// signedInfoInherited mirrors signedInfo.
	signedInfoInherited []map[string]string
	// inheritedAt records the namespace scope in force at each ID'd element.
	inheritedAt map[int]map[string]string

	signatureMethod []string
	digestMethod    []string
	digestValue     []string
	signatureValue  []string
	referenceURI    []string
	c14nMethod      []string
	transforms      []string
	assertions      int
	pendingText     *string
}

func (s *scanner) consume(token xml.Token, start, end int64) error {
	switch typed := token.(type) {
	case xml.Directive:
		return ErrDoctype
	case xml.StartElement:
		return s.openElement(typed, start)
	case xml.EndElement:
		s.closeElement(end)
	case xml.CharData:
		if s.pendingText != nil {
			*s.pendingText += string(typed)
		}
	}
	return nil
}

func (s *scanner) openElement(start xml.StartElement, offset int64) error {
	s.depth++
	if s.depth > maxDepth {
		return fmt.Errorf("the SAML document nests deeper than %d elements", maxDepth)
	}
	s.scopes = append(s.scopes, declarationMap(start))
	resolved := xml.Name{Space: s.resolvePrefix(start.Name.Space), Local: start.Name.Local}
	s.open = append(s.open, element{
		Name:  resolved,
		ID:    attributeValue(start, "ID"),
		Start: int(offset),
		Depth: s.depth,
	})
	s.recordInterest(resolved, start)
	return nil
}

// recordInterest notes the elements and attributes Verify will need.
func (s *scanner) recordInterest(name xml.Name, start xml.StartElement) {
	s.pendingText = nil
	if name.Space != namespaceSignature {
		if name.Space == namespaceAssertion && name.Local == "Assertion" {
			s.assertions++
		}
		return
	}
	switch name.Local {
	case "SignatureMethod":
		s.signatureMethod = append(s.signatureMethod, attributeValue(start, "Algorithm"))
	case "DigestMethod":
		s.digestMethod = append(s.digestMethod, attributeValue(start, "Algorithm"))
	case "CanonicalizationMethod":
		s.c14nMethod = append(s.c14nMethod, attributeValue(start, "Algorithm"))
	case "Transform":
		s.transforms = append(s.transforms, attributeValue(start, "Algorithm"))
	case "Reference":
		s.referenceURI = append(s.referenceURI, attributeValue(start, "URI"))
	case "DigestValue":
		s.digestValue = append(s.digestValue, "")
		s.pendingText = &s.digestValue[len(s.digestValue)-1]
	case "SignatureValue":
		s.signatureValue = append(s.signatureValue, "")
		s.pendingText = &s.signatureValue[len(s.signatureValue)-1]
	}
}

func (s *scanner) closeElement(offset int64) {
	if len(s.open) == 0 {
		return
	}
	current := s.open[len(s.open)-1]
	s.open = s.open[:len(s.open)-1]
	inherited := s.flattenScope(len(s.scopes) - 1)
	s.scopes = s.scopes[:len(s.scopes)-1]
	s.depth--
	current.End = int(offset)

	if current.ID != "" {
		if s.inheritedAt == nil {
			s.inheritedAt = map[int]map[string]string{}
		}
		s.inheritedAt[len(s.withID)] = inherited
		s.withID = append(s.withID, current)
	}
	if current.Name.Space == namespaceSignature {
		switch current.Name.Local {
		case "Signature":
			s.signatures = append(s.signatures, current)
		case "SignedInfo":
			s.signedInfo = append(s.signedInfo, current)
			s.signedInfoInherited = append(s.signedInfoInherited, inherited)
		}
	}
	s.pendingText = nil
}

// flattenScope collects the bindings in force *outside* the level at index,
// which is what an element inherits.
func (s *scanner) flattenScope(index int) map[string]string {
	inherited := map[string]string{}
	for level := 0; level < index; level++ {
		for prefix, uri := range s.scopes[level] {
			inherited[prefix] = uri
		}
	}
	return inherited
}

// resolvePrefix maps a prefix onto its URI using the scope stack, innermost
// first. The current element's own declarations are already on the stack.
func (s *scanner) resolvePrefix(prefix string) string {
	for index := len(s.scopes) - 1; index >= 0; index-- {
		if uri, found := s.scopes[index][prefix]; found {
			return uri
		}
	}
	return prefix
}

// resolve turns the scan into a verified-single answer, or refuses.
func (s *scanner) resolve() (located, error) {
	if len(s.signatures) == 0 {
		return located{}, ErrNoSignature
	}
	if err := s.refuseAmbiguity(); err != nil {
		return located{}, err
	}
	signed, inherited, err := s.referencedElement()
	if err != nil {
		return located{}, err
	}
	if err := s.requireEnvelopedTransform(); err != nil {
		return located{}, err
	}
	withComments, err := canonicalizationMode(s.c14nMethod[0])
	if err != nil {
		return located{}, err
	}
	return located{
		Signature:           s.signatures[0],
		SignedInfo:          s.signedInfo[0],
		Signed:              signed,
		SignatureMethod:     s.signatureMethod[0],
		DigestMethod:        s.digestMethod[0],
		DigestValue:         s.digestValue[0],
		SignatureValue:      s.signatureValue[0],
		C14NWithComments:    withComments,
		Inherited:           inherited,
		SignedInfoInherited: s.signedInfoInherited[0],
	}, nil
}

// refuseAmbiguity rejects every document that could be read two ways.
func (s *scanner) refuseAmbiguity() error {
	counts := map[string]int{
		"Signature":              len(s.signatures),
		"SignedInfo":             len(s.signedInfo),
		"SignatureMethod":        len(s.signatureMethod),
		"DigestMethod":           len(s.digestMethod),
		"DigestValue":            len(s.digestValue),
		"SignatureValue":         len(s.signatureValue),
		"Reference":              len(s.referenceURI),
		"CanonicalizationMethod": len(s.c14nMethod),
	}
	for name, count := range counts {
		if count != 1 {
			return fmt.Errorf("%w: the document carries %d %s elements, expected exactly 1",
				ErrAmbiguous, count, name)
		}
	}
	// More than one assertion is the classic wrapping shape: one signed, one
	// read. SESAME will not carry two.
	if s.assertions > 1 {
		return fmt.Errorf("%w: the document carries %d assertions", ErrAmbiguous, s.assertions)
	}
	return nil
}

// referencedElement resolves the Reference URI to exactly one element.
func (s *scanner) referencedElement() (element, map[string]string, error) {
	uri := strings.TrimSpace(s.referenceURI[0])
	// An empty URI means "the whole document", which SESAME refuses: it makes
	// the signed scope depend on where the reader stops rather than on an
	// identifier both sides agree about.
	if !strings.HasPrefix(uri, "#") || len(uri) == 1 {
		return element{}, nil, fmt.Errorf(
			"%w: the reference URI %q must name an element by fragment", ErrAmbiguous, uri)
	}
	wanted := uri[1:]

	var found []int
	for index, candidate := range s.withID {
		if candidate.ID == wanted {
			found = append(found, index)
		}
	}
	if len(found) != 1 {
		// Zero means the reference points at nothing; more than one means the
		// document reuses an identifier, which is the other wrapping shape.
		return element{}, nil, fmt.Errorf(
			"%w: the reference %q matches %d elements, expected exactly 1",
			ErrAmbiguous, uri, len(found))
	}
	index := found[0]
	return s.withID[index], s.inheritedAt[index], nil
}

// requireEnvelopedTransform insists the signature declares that it excludes
// itself. A reference without it describes a digest over bytes that include
// the signature, which cannot be what was computed.
func (s *scanner) requireEnvelopedTransform() error {
	for _, transform := range s.transforms {
		if transform == transformEnvelopedSignature {
			return nil
		}
	}
	return fmt.Errorf("%w: the reference declares no enveloped-signature transform",
		ErrAmbiguous)
}

func canonicalizationMode(algorithm string) (bool, error) {
	switch algorithm {
	case algorithmExclusiveC14N:
		return false, nil
	case algorithmExclusiveC14NWithComments:
		return true, nil
	default:
		return false, fmt.Errorf(
			"%w: canonicalization %q; SESAME supports exclusive canonicalization only",
			ErrUnsupportedAlgorithm, algorithm)
	}
}

func declarationMap(start xml.StartElement) map[string]string {
	declared := map[string]string{}
	for _, attribute := range start.Attr {
		if attribute.Name.Space == "xmlns" {
			declared[attribute.Name.Local] = attribute.Value
			continue
		}
		if attribute.Name.Space == "" && attribute.Name.Local == "xmlns" {
			declared[""] = attribute.Value
		}
	}
	return declared
}

func attributeValue(start xml.StartElement, name string) string {
	for _, attribute := range start.Attr {
		if attribute.Name.Local == name && attribute.Name.Space == "" {
			return attribute.Value
		}
	}
	return ""
}
