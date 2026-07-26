package saml

import (
	"encoding/xml"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	testIssuer    = "https://idp.example/metadata"
	testAudience  = "https://sesame.example/sp"
	testRecipient = "https://app.example/saml/acs"
	testRequestID = "_req1"
)

var testNow = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// assertionDocument renders an assertion with fields overridable one at a
// time, so a refusal is attributable to exactly one change.
func assertionDocument(overrides map[string]string) string {
	values := map[string]string{
		"issuer":        testIssuer,
		"subject":       "alice@example.com",
		"inResponseTo":  testRequestID,
		"recipient":     testRecipient,
		"notBefore":     testNow.Add(-time.Minute).Format(time.RFC3339),
		"notOnOrAfter":  testNow.Add(5 * time.Minute).Format(time.RFC3339),
		"audience":      testAudience,
		"method":        BearerConfirmation,
		"extraConfirm":  "",
		"extraAudience": "",
	}
	for key, value := range overrides {
		values[key] = value
	}
	confirmation := `<saml:SubjectConfirmation Method="` + values["method"] + `">` +
		`<saml:SubjectConfirmationData InResponseTo="` + values["inResponseTo"] +
		`" Recipient="` + values["recipient"] + `"/></saml:SubjectConfirmation>`

	return `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1">` +
		`<saml:Issuer>` + values["issuer"] + `</saml:Issuer>` +
		`<saml:Subject><saml:NameID>` + values["subject"] + `</saml:NameID>` +
		confirmation + values["extraConfirm"] + `</saml:Subject>` +
		`<saml:Conditions NotBefore="` + values["notBefore"] +
		`" NotOnOrAfter="` + values["notOnOrAfter"] + `">` +
		`<saml:AudienceRestriction><saml:Audience>` + values["audience"] +
		`</saml:Audience>` + values["extraAudience"] + `</saml:AudienceRestriction>` +
		`</saml:Conditions>` +
		`<saml:AttributeStatement><saml:Attribute Name="groups">` +
		`<saml:AttributeValue>engineering</saml:AttributeValue>` +
		`<saml:AttributeValue>oncall</saml:AttributeValue>` +
		`</saml:Attribute></saml:AttributeStatement>` +
		`</saml:Assertion>`
}

// signedOf wraps a document as though verification had already succeeded.
// ParseAssertion takes a Signed precisely so this cannot happen by accident
// in production code.
func signedOf(document string) Signed {
	return Signed{
		Element: []byte(document),
		Name:    xml.Name{Space: namespaceAssertion, Local: "Assertion"},
		ID:      "_a1",
	}
}

func defaultExpectation() Expectation {
	return Expectation{
		Issuer:    testIssuer,
		Audience:  testAudience,
		Recipient: testRecipient,
		RequestID: testRequestID,
		Now:       testNow,
	}
}

func TestParseAssertionReadsTheVerifiedElement(t *testing.T) {
	t.Parallel()

	assertion, err := ParseAssertion(signedOf(assertionDocument(nil)))
	if err != nil {
		t.Fatalf("ParseAssertion() error = %v", err)
	}
	if assertion.Subject != "alice@example.com" || assertion.Issuer != testIssuer {
		t.Fatalf("parsed %#v", assertion)
	}
	groups := assertion.Attributes["groups"]
	if len(groups) != 2 || groups[0] != "engineering" || groups[1] != "oncall" {
		t.Fatalf("attributes = %#v", assertion.Attributes)
	}
	if err := assertion.Check(defaultExpectation()); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
}

// TestParseAssertionRefusesASignatureOverTheWrongElement: a signature over a
// Response says nothing about an Assertion inside it, and treating one as the
// other is how a signed-response/unsigned-assertion bypass works.
func TestParseAssertionRefusesASignatureOverTheWrongElement(t *testing.T) {
	t.Parallel()

	signed := signedOf(assertionDocument(nil))
	signed.Name = xml.Name{Space: namespaceProtocol, Local: "Response"}
	if _, err := ParseAssertion(signed); !errors.Is(err, ErrSubjectUnusable) {
		t.Fatalf("error = %v, want ErrSubjectUnusable", err)
	}
}

// TestCheckRefusesWhatASignatureDoesNotAnswer covers the three questions a
// valid signature leaves open: was this written for SESAME, for this login,
// and now.
func TestCheckRefusesWhatASignatureDoesNotAnswer(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		overrides map[string]string
		expected  func(Expectation) Expectation
		want      error
	}{
		// A different identity provider's assertion, correctly signed by that
		// provider, is not this provider vouching for anyone.
		"wrong issuer": {
			overrides: map[string]string{"issuer": "https://evil.example/metadata"},
			want:      ErrRequestMismatch,
		},
		// Without this, an assertion captured at any other service provider
		// the same identity provider serves replays here.
		"wrong audience": {
			overrides: map[string]string{"audience": "https://other.example/sp"},
			want:      ErrAudienceMismatch,
		},
		"no audience at all": {
			overrides: map[string]string{"audience": "", "extraAudience": ""},
			want:      ErrAudienceMismatch,
		},
		// An assertion delivered to a different consumer URL was not meant
		// for this endpoint.
		"wrong recipient": {
			overrides: map[string]string{"recipient": "https://evil.example/acs"},
			want:      ErrRequestMismatch,
		},
		// An unsolicited assertion has no binding to a request SESAME sent,
		// which is the binding that makes a stolen one useless elsewhere.
		"unsolicited": {
			overrides: map[string]string{"inResponseTo": ""},
			want:      ErrRequestMismatch,
		},
		"answers another login": {
			overrides: map[string]string{"inResponseTo": "_someone-elses-request"},
			want:      ErrRequestMismatch,
		},
		"expired beyond skew": {
			overrides: map[string]string{
				"notOnOrAfter": testNow.Add(-2 * time.Minute).Format(time.RFC3339),
			},
			want: ErrAssertionExpired,
		},
		"not yet valid": {
			overrides: map[string]string{
				"notBefore": testNow.Add(2 * time.Minute).Format(time.RFC3339),
			},
			want: ErrAssertionExpired,
		},
		// An assertion that never expires makes a single capture permanent.
		"no expiry": {
			overrides: map[string]string{"notOnOrAfter": ""},
			want:      ErrAssertionExpired,
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assertion, err := ParseAssertion(signedOf(assertionDocument(testCase.overrides)))
			if err != nil {
				t.Fatalf("ParseAssertion() error = %v", err)
			}
			expectation := defaultExpectation()
			if testCase.expected != nil {
				expectation = testCase.expected(expectation)
			}
			if err := assertion.Check(expectation); !errors.Is(err, testCase.want) {
				t.Fatalf("Check() error = %v, want %v", err, testCase.want)
			}
		})
	}
}

// TestCheckToleratesClockSkewInBothDirections: refusing a valid assertion
// because two clocks disagree by seconds is an outage, not a defence.
func TestCheckToleratesClockSkewInBothDirections(t *testing.T) {
	t.Parallel()

	assertion, err := ParseAssertion(signedOf(assertionDocument(map[string]string{
		"notBefore":    testNow.Add(30 * time.Second).Format(time.RFC3339),
		"notOnOrAfter": testNow.Add(90 * time.Second).Format(time.RFC3339),
	})))
	if err != nil {
		t.Fatalf("ParseAssertion() error = %v", err)
	}
	// Thirty seconds early is inside the sixty-second tolerance.
	if err := assertion.Check(defaultExpectation()); err != nil {
		t.Fatalf("Check() rejected an assertion inside the skew window: %v", err)
	}
	// Two minutes early is not.
	early := defaultExpectation()
	early.Now = testNow.Add(-2 * time.Minute)
	if err := assertion.Check(early); !errors.Is(err, ErrAssertionExpired) {
		t.Fatalf("Check() error = %v, want ErrAssertionExpired", err)
	}
}

// TestParseAssertionRequiresExactlyOneBearerConfirmation: choosing between
// several would mean deciding which of an attacker's alternatives to honour.
func TestParseAssertionRequiresExactlyOneBearerConfirmation(t *testing.T) {
	t.Parallel()

	t.Run("none", func(t *testing.T) {
		document := assertionDocument(map[string]string{
			"method": "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key",
		})
		if _, err := ParseAssertion(signedOf(document)); !errors.Is(err, ErrSubjectUnusable) {
			t.Fatalf("error = %v, want ErrSubjectUnusable", err)
		}
	})

	t.Run("two", func(t *testing.T) {
		second := `<saml:SubjectConfirmation Method="` + BearerConfirmation + `">` +
			`<saml:SubjectConfirmationData InResponseTo="_other" ` +
			`Recipient="https://evil.example/acs"/></saml:SubjectConfirmation>`
		document := assertionDocument(map[string]string{"extraConfirm": second})
		if _, err := ParseAssertion(signedOf(document)); !errors.Is(err, ErrSubjectUnusable) {
			t.Fatalf("error = %v, want ErrSubjectUnusable", err)
		}
	})
}

func TestParseAssertionRefusesAnEmptySubject(t *testing.T) {
	t.Parallel()

	document := assertionDocument(map[string]string{"subject": "   "})
	if _, err := ParseAssertion(signedOf(document)); !errors.Is(err, ErrSubjectUnusable) {
		t.Fatalf("error = %v, want ErrSubjectUnusable", err)
	}
}

// TestCheckAcceptsAMatchingAudienceAmongSeveral: naming several audiences is
// legal, and refusing it would break legitimate providers.
func TestCheckAcceptsAMatchingAudienceAmongSeveral(t *testing.T) {
	t.Parallel()

	document := assertionDocument(map[string]string{
		"audience":      "https://other.example/sp",
		"extraAudience": `<saml:Audience>` + testAudience + `</saml:Audience>`,
	})
	assertion, err := ParseAssertion(signedOf(document))
	if err != nil {
		t.Fatalf("ParseAssertion() error = %v", err)
	}
	if err := assertion.Check(defaultExpectation()); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
}

// TestReplayKeySeparatesIssuers: two providers may legitimately mint the same
// assertion identifier, and collapsing them would let one provider's
// assertion block another's.
func TestReplayKeySeparatesIssuers(t *testing.T) {
	t.Parallel()

	first := ReplayKey("https://a.example", "_shared")
	second := ReplayKey("https://b.example", "_shared")
	if first == second {
		t.Fatal("the same assertion ID at two issuers hashes identically")
	}
	if first != ReplayKey("https://a.example", "_shared") {
		t.Fatal("ReplayKey is not deterministic")
	}
	// The length prefix stops issuer and identifier being shifted across the
	// separator, as it does for federation subjects.
	if ReplayKey("a", "b:c") == ReplayKey("a:b", "c") {
		t.Fatal("issuer and assertion ID can be shifted across the separator")
	}
}

func TestParseInstantRefusesMalformedTimestamps(t *testing.T) {
	t.Parallel()

	document := assertionDocument(map[string]string{"notOnOrAfter": "not-a-timestamp"})
	if _, err := ParseAssertion(signedOf(document)); err == nil {
		t.Fatal("ParseAssertion accepted a malformed timestamp")
	} else if !strings.Contains(err.Error(), "RFC 3339") {
		t.Fatalf("error = %v, want it to name the format", err)
	}
}
