package saml

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
)

const (
	// EventProviderRegistered records a new SAML identity provider.
	EventProviderRegistered = "saml.provider_registered"
	// EventProviderDisabled records a durable provider shutdown.
	EventProviderDisabled = "saml.provider_disabled"
	// EventLoginStarted records an authentication request leaving.
	EventLoginStarted = "saml.login_started"
	// EventLoginCompleted records a verified assertion becoming a session.
	EventLoginCompleted = "saml.login_completed"
	// EventLoginFailed records a rejected assertion, with a reason.
	EventLoginFailed = "saml.login_failed"

	// MaxClockSkew tolerates modest disagreement between the provider's clock
	// and this host's. It matches what SESAME allows its own tokens.
	MaxClockSkew = 60 * time.Second

	// BearerConfirmation is the only subject confirmation method SESAME
	// accepts. Holder-of-key and sender-vouches require key material or a
	// trusted intermediary that a web SSO deployment does not have.
	BearerConfirmation = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
)

var (
	// ErrAssertionExpired reports an assertion outside its validity window.
	ErrAssertionExpired = errors.New("the SAML assertion is outside its validity window")
	// ErrAudienceMismatch reports an assertion issued for somebody else.
	ErrAudienceMismatch = errors.New("the SAML assertion is not addressed to this service provider")
	// ErrSubjectUnusable reports a subject SESAME cannot act on.
	ErrSubjectUnusable = errors.New("the SAML assertion carries no usable subject")
	// ErrRequestMismatch reports an assertion that does not answer the
	// request SESAME made.
	ErrRequestMismatch = errors.New("the SAML assertion does not answer this login")
)

// Assertion is what SESAME reads out of a verified element.
//
// Every field here comes from the byte range the signature covered. Nothing
// is read from the surrounding document, which is what makes wrapping
// irrelevant to this type: there is no unsigned data in it.
type Assertion struct {
	ID            string
	Issuer        string
	Subject       string
	SubjectFormat string
	// InResponseTo binds the assertion to the request SESAME sent.
	InResponseTo string
	Recipient    string
	NotBefore    time.Time
	NotOnOrAfter time.Time
	// SessionNotOnOrAfter, when present, is the provider's opinion about how
	// long the session it authorises should last.
	SessionNotOnOrAfter time.Time
	Audiences           []string
	Attributes          map[string][]string
}

// assertionXML mirrors the subset of RFC-defined structure SESAME reads.
type assertionXML struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID      string   `xml:"ID,attr"`
	Issuer  string   `xml:"Issuer"`
	Subject struct {
		NameID struct {
			Format string `xml:"Format,attr"`
			Value  string `xml:",chardata"`
		} `xml:"NameID"`
		Confirmations []struct {
			Method string `xml:"Method,attr"`
			Data   struct {
				InResponseTo string `xml:"InResponseTo,attr"`
				Recipient    string `xml:"Recipient,attr"`
				NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
			} `xml:"SubjectConfirmationData"`
		} `xml:"SubjectConfirmation"`
	} `xml:"Subject"`
	Conditions struct {
		NotBefore    string `xml:"NotBefore,attr"`
		NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
		Audiences    []struct {
			Values []string `xml:"Audience"`
		} `xml:"AudienceRestriction"`
	} `xml:"Conditions"`
	AuthnStatements []struct {
		SessionNotOnOrAfter string `xml:"SessionNotOnOrAfter,attr"`
	} `xml:"AuthnStatement"`
	AttributeStatements []struct {
		Attributes []struct {
			Name   string   `xml:"Name,attr"`
			Values []string `xml:"AttributeValue"`
		} `xml:"Attribute"`
	} `xml:"AttributeStatement"`
}

// ParseAssertion reads a verified element.
//
// It takes a Signed rather than raw bytes so a caller cannot accidentally
// hand it an unverified document. The type system carries the guarantee that
// verification already happened.
func ParseAssertion(signed Signed) (Assertion, error) {
	if signed.Name.Space != namespaceAssertion || signed.Name.Local != "Assertion" {
		return Assertion{}, fmt.Errorf(
			"%w: the signature covers a %s, not an Assertion", ErrSubjectUnusable, signed.Name.Local)
	}
	var parsed assertionXML
	if err := decodeInScope(signed, &parsed); err != nil {
		return Assertion{}, fmt.Errorf("the SAML assertion is unreadable: %w", err)
	}
	return buildAssertion(parsed)
}

// namespaceContextElement wraps a signed element so its ancestors' namespace
// declarations are in scope while it is parsed. The name is deliberately not
// one any SAML document uses.
const namespaceContextElement = "sesame-namespace-context"

// decodeInScope parses a verified element with its inherited namespace
// bindings restored.
//
// The element is re-declared inside a synthetic parent rather than edited, so
// the bytes that were verified are the bytes that are read — the wrapping
// defence is untouched, because there is still exactly one place to read from
// and it is still the signed range.
func decodeInScope(signed Signed, target any) error {
	var document strings.Builder
	document.WriteString("<" + namespaceContextElement)
	for _, prefix := range slices.Sorted(maps.Keys(signed.Inherited)) {
		// A prefix comes from a parsed xmlns attribute, so it cannot contain a
		// quote — but it is attacker-influenced, and building markup from it
		// without checking is how that stops being true.
		if prefix != "" && !validNamespacePrefix(prefix) {
			continue
		}
		document.WriteString(" xmlns")
		if prefix != "" {
			document.WriteString(":" + prefix)
		}
		document.WriteString(`="`)
		var escaped strings.Builder
		if err := xml.EscapeText(&escaped, []byte(signed.Inherited[prefix])); err != nil {
			return err
		}
		document.WriteString(escaped.String())
		document.WriteString(`"`)
	}
	document.WriteString(">")
	document.Write(signed.Element)
	document.WriteString("</" + namespaceContextElement + ">")

	decoder := xml.NewDecoder(strings.NewReader(document.String()))
	// The first start element is the synthetic parent; the second is the
	// signed element itself, now with every prefix resolvable.
	seenWrapper := false
	for {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if !seenWrapper {
			seenWrapper = true
			continue
		}
		return decoder.DecodeElement(target, &start)
	}
}

// validNamespacePrefix accepts the conservative subset of an XML NCName that
// cannot change the meaning of the markup it is written into.
func validNamespacePrefix(prefix string) bool {
	for index, character := range prefix {
		switch {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character == '_':
		case index > 0 && (character >= '0' && character <= '9' ||
			character == '-' || character == '.'):
		default:
			return false
		}
	}
	return prefix != ""
}

func buildAssertion(parsed assertionXML) (Assertion, error) {
	subject := strings.TrimSpace(parsed.Subject.NameID.Value)
	if subject == "" {
		return Assertion{}, ErrSubjectUnusable
	}
	confirmation, err := bearerConfirmation(parsed)
	if err != nil {
		return Assertion{}, err
	}
	notBefore, err := parseInstant(parsed.Conditions.NotBefore)
	if err != nil {
		return Assertion{}, err
	}
	notOnOrAfter, err := parseInstant(parsed.Conditions.NotOnOrAfter)
	if err != nil {
		return Assertion{}, err
	}
	return Assertion{
		ID:                  parsed.ID,
		Issuer:              strings.TrimSpace(parsed.Issuer),
		Subject:             subject,
		SubjectFormat:       parsed.Subject.NameID.Format,
		InResponseTo:        confirmation.InResponseTo,
		Recipient:           confirmation.Recipient,
		NotBefore:           notBefore,
		NotOnOrAfter:        notOnOrAfter,
		SessionNotOnOrAfter: sessionExpiry(parsed),
		Audiences:           audiencesOf(parsed),
		Attributes:          attributesOf(parsed),
	}, nil
}

type confirmationData struct {
	InResponseTo string
	Recipient    string
	NotOnOrAfter time.Time
}

// bearerConfirmation resolves the one confirmation SESAME acts on.
//
// Several confirmations are legal; SESAME requires exactly one bearer, for
// the same reason locate refuses two assertions. Choosing between them would
// mean deciding which of an attacker's alternatives to honour.
func bearerConfirmation(parsed assertionXML) (confirmationData, error) {
	var found []confirmationData
	for _, confirmation := range parsed.Subject.Confirmations {
		if confirmation.Method != BearerConfirmation {
			continue
		}
		expiry, err := parseInstant(confirmation.Data.NotOnOrAfter)
		if err != nil {
			return confirmationData{}, err
		}
		found = append(found, confirmationData{
			InResponseTo: confirmation.Data.InResponseTo,
			Recipient:    confirmation.Data.Recipient,
			NotOnOrAfter: expiry,
		})
	}
	if len(found) != 1 {
		return confirmationData{}, fmt.Errorf(
			"%w: the assertion carries %d bearer confirmations, expected exactly 1",
			ErrSubjectUnusable, len(found))
	}
	return found[0], nil
}

func sessionExpiry(parsed assertionXML) time.Time {
	for _, statement := range parsed.AuthnStatements {
		if instant, err := parseInstant(statement.SessionNotOnOrAfter); err == nil {
			return instant
		}
	}
	return time.Time{}
}

func audiencesOf(parsed assertionXML) []string {
	var audiences []string
	for _, restriction := range parsed.Conditions.Audiences {
		for _, value := range restriction.Values {
			audiences = append(audiences, strings.TrimSpace(value))
		}
	}
	return audiences
}

func attributesOf(parsed assertionXML) map[string][]string {
	attributes := map[string][]string{}
	for _, statement := range parsed.AttributeStatements {
		for _, attribute := range statement.Attributes {
			for _, value := range attribute.Values {
				attributes[attribute.Name] = append(attributes[attribute.Name],
					strings.TrimSpace(value))
			}
		}
	}
	return attributes
}

// parseInstant reads a SAML timestamp, which is always UTC ISO 8601.
func parseInstant(value string) (time.Time, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}, nil
	}
	instant, err := time.Parse(time.RFC3339, trimmed)
	if err != nil {
		return time.Time{}, fmt.Errorf("the SAML instant %q is not RFC 3339: %w", value, err)
	}
	return instant.UTC(), nil
}

// Expectation is what SESAME requires of an assertion, beyond its signature.
type Expectation struct {
	// Issuer is the provider's registered entity ID. An assertion from
	// somebody else is not one this provider vouched for.
	Issuer string
	// Audience is SESAME's own entity ID, which the assertion must name.
	Audience string
	// Recipient is the assertion consumer URL. It must match, or an
	// assertion captured at one service provider replays at another.
	Recipient string
	// RequestID is the AuthnRequest SESAME sent. Binding to it is what makes
	// an unsolicited assertion refusable.
	RequestID string
	Now       time.Time
}

// Check applies every condition an assertion must satisfy.
//
// Signature verification proved who wrote it. This proves it was written for
// SESAME, for this login, and now — three questions a valid signature does
// not answer, and each of which has its own bypass if skipped.
func (a Assertion) Check(expected Expectation) error {
	if a.Issuer != expected.Issuer {
		return fmt.Errorf("%w: the assertion is issued by %q, not %q",
			ErrRequestMismatch, a.Issuer, expected.Issuer)
	}
	if err := a.checkWindow(expected.Now); err != nil {
		return err
	}
	if err := a.checkAudience(expected.Audience); err != nil {
		return err
	}
	return a.checkDelivery(expected)
}

// checkWindow enforces the validity window with bounded skew.
func (a Assertion) checkWindow(now time.Time) error {
	if !a.NotBefore.IsZero() && now.Add(MaxClockSkew).Before(a.NotBefore) {
		return fmt.Errorf("%w: it is not valid until %s", ErrAssertionExpired, a.NotBefore)
	}
	// An assertion with no expiry never stops being usable, which makes a
	// single capture permanent.
	if a.NotOnOrAfter.IsZero() {
		return fmt.Errorf("%w: the assertion declares no expiry", ErrAssertionExpired)
	}
	if !now.Add(-MaxClockSkew).Before(a.NotOnOrAfter) {
		return fmt.Errorf("%w: it expired at %s", ErrAssertionExpired, a.NotOnOrAfter)
	}
	return nil
}

// checkAudience refuses an assertion addressed to a different service.
//
// Without this an assertion captured at any other service provider the same
// identity provider serves would be replayable here.
func (a Assertion) checkAudience(audience string) error {
	if len(a.Audiences) == 0 {
		return fmt.Errorf("%w: the assertion names no audience", ErrAudienceMismatch)
	}
	for _, candidate := range a.Audiences {
		if candidate == audience {
			return nil
		}
	}
	return fmt.Errorf("%w: it names %s", ErrAudienceMismatch, strings.Join(a.Audiences, ", "))
}

// checkDelivery enforces where the assertion was meant to arrive and which
// request it answers.
func (a Assertion) checkDelivery(expected Expectation) error {
	if a.Recipient != expected.Recipient {
		return fmt.Errorf("%w: it was issued for %q, not %q",
			ErrRequestMismatch, a.Recipient, expected.Recipient)
	}
	// SESAME does not accept unsolicited assertions. An identity provider
	// initiating login without a request SESAME sent removes the binding that
	// makes a stolen assertion useless elsewhere.
	if expected.RequestID == "" || a.InResponseTo != expected.RequestID {
		return fmt.Errorf("%w: it answers %q, not this login",
			ErrRequestMismatch, a.InResponseTo)
	}
	return nil
}

// ReplayKey identifies an assertion for single-use enforcement.
//
// The identifier is bound to its issuer before hashing: two providers may
// legitimately mint the same ID, and collapsing them would let one provider's
// assertion block another's.
func ReplayKey(issuer, assertionID string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%s:%s", len(issuer), issuer, assertionID)))
	return hex.EncodeToString(sum[:])
}
