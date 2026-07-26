package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	authndomain "github.com/d31ma/sesame/internal/domain/authentication"
	samldomain "github.com/d31ma/sesame/internal/domain/saml"
	"github.com/d31ma/sesame/internal/domain/saml/samltest"
)

const (
	samlEntityID    = "https://idp.example.com/metadata"
	samlSSOURL      = "https://idp.example.com/sso"
	samlConsumerURL = "https://app.example.com/saml/acs"
	samlAudience    = "https://sesame.example.com"
)

// samlFixture is a tenant with one registered SAML provider and a stand-in
// identity provider that can sign assertions.
type samlFixture struct {
	service    *Service
	ledger     *memoryLedger
	tenantID   string
	providerID string
	signer     *samltest.Signer
	now        time.Time
}

func newSAMLFixture(t *testing.T, linking string) *samlFixture {
	t.Helper()

	service, ledger, tenantID := bootstrapService(t)
	service.UseIssuer(samlAudience)

	signer, err := samltest.NewSigner("idp.example.com")
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	fixture := &samlFixture{
		service:  service,
		ledger:   ledger,
		tenantID: tenantID,
		signer:   signer,
		now:      time.Unix(1_700_000_000, 0).UTC(),
	}
	service.UseClock(func() time.Time { return fixture.now })

	provider, err := service.SAMLProviderRegister(context.Background(), tenantID,
		"Corp SSO", samlEntityID, samlSSOURL, []string{signer.PEM}, "email",
		linking, "test")
	if err != nil {
		t.Fatalf("SAMLProviderRegister() error = %v", err)
	}
	fixture.providerID = provider.ID
	return fixture
}

// assertion renders an assertion answering a login, with fields overridable.
func (f *samlFixture) assertion(login SAMLLogin) samltest.Assertion {
	return samltest.Assertion{
		ID:           "_assertion-1",
		Issuer:       samlEntityID,
		Subject:      "alice@example.com",
		Audience:     samlAudience,
		Recipient:    samlConsumerURL,
		RequestID:    login.RequestID,
		NotBefore:    f.now.Add(-time.Minute),
		NotOnOrAfter: f.now.Add(5 * time.Minute),
	}
}

func (f *samlFixture) start(t *testing.T) SAMLLogin {
	t.Helper()

	login, err := f.service.SAMLLoginStart(context.Background(), f.tenantID,
		f.providerID, samlConsumerURL, "test")
	if err != nil {
		t.Fatalf("SAMLLoginStart() error = %v", err)
	}
	return login
}

func (f *samlFixture) complete(
	t *testing.T,
	login SAMLLogin,
	assertion samltest.Assertion,
) (SAMLSession, error) {
	t.Helper()

	document, err := f.signer.Sign(assertion.Document())
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return f.service.SAMLLoginComplete(context.Background(), f.tenantID,
		login.LoginID, []byte(document), "test")
}

// TestSAMLLoginProvisionsAndIssuesAFederatedSession is the happy path, and it
// checks the assurance level: SESAME did not witness the credential, so the
// session must not claim it did.
func TestSAMLLoginProvisionsAndIssuesAFederatedSession(t *testing.T) {
	t.Parallel()

	fixture := newSAMLFixture(t, federationEmailLinking)
	login := fixture.start(t)

	// The AuthnRequest must name SESAME and carry the unguessable ID the
	// assertion has to answer.
	if !strings.Contains(login.AuthnRequest, samlAudience) {
		t.Fatalf("the AuthnRequest does not name the deployment issuer: %s", login.AuthnRequest)
	}
	if !strings.Contains(login.AuthnRequest, login.RequestID) {
		t.Fatalf("the AuthnRequest does not carry its own request ID")
	}
	if login.Destination != samlSSOURL {
		t.Fatalf("destination = %q", login.Destination)
	}

	result, err := fixture.complete(t, login, fixture.assertion(login))
	if err != nil {
		t.Fatalf("SAMLLoginComplete() error = %v", err)
	}
	if !result.Provisioned {
		t.Fatal("the first login for an unknown subject did not provision a principal")
	}
	verified, err := fixture.service.SessionVerify(result.Session.SessionID,
		result.Session.Secret)
	if err != nil {
		t.Fatalf("SessionVerify() error = %v", err)
	}
	if verified.Assurance != authndomain.AssuranceFederated {
		t.Fatalf("assurance = %q, want %q", verified.Assurance, authndomain.AssuranceFederated)
	}
}

// TestSAMLLoginLinksTheSameSubjectToOnePrincipal: a second login must reuse
// the principal, or every sign-in would mint a new identity.
func TestSAMLLoginLinksTheSameSubjectToOnePrincipal(t *testing.T) {
	t.Parallel()

	fixture := newSAMLFixture(t, federationEmailLinking)
	login := fixture.start(t)
	firstResult, err := fixture.complete(t, login, fixture.assertion(login))
	if err != nil {
		t.Fatalf("first SAMLLoginComplete() error = %v", err)
	}

	second := fixture.start(t)
	assertion := fixture.assertion(second)
	assertion.ID = "_assertion-2"
	secondResult, err := fixture.complete(t, second, assertion)
	if err != nil {
		t.Fatalf("second SAMLLoginComplete() error = %v", err)
	}
	if secondResult.PrincipalID != firstResult.PrincipalID {
		t.Fatalf("principal %q then %q", firstResult.PrincipalID, secondResult.PrincipalID)
	}
	if secondResult.Provisioned {
		t.Fatal("the second login provisioned a second principal")
	}
}

// TestSAMLStrictLinkingRefusesAnUnknownSubject: under strict linking a
// verified assertion is not by itself an authorization to create an account.
func TestSAMLStrictLinkingRefusesAnUnknownSubject(t *testing.T) {
	t.Parallel()

	fixture := newSAMLFixture(t, federationStrictLinking)
	login := fixture.start(t)
	if _, err := fixture.complete(t, login, fixture.assertion(login)); !errors.Is(
		err, ErrSAMLSubjectNotLinked) {
		t.Fatalf("error = %v, want ErrSAMLSubjectNotLinked", err)
	}
}

// TestSAMLLoginRefusesAReplayedAssertion is the single-use guarantee. A
// captured assertion inside its validity window must be worth nothing twice,
// even against a freshly started login.
func TestSAMLLoginRefusesAReplayedAssertion(t *testing.T) {
	t.Parallel()

	fixture := newSAMLFixture(t, federationEmailLinking)
	login := fixture.start(t)
	assertion := fixture.assertion(login)
	if _, err := fixture.complete(t, login, assertion); err != nil {
		t.Fatalf("SAMLLoginComplete() error = %v", err)
	}

	// A second login whose request ID the attacker rewrites the assertion to
	// answer would still fail on the signature; instead give the replay the
	// best possible chance by reusing the same request ID.
	second := fixture.start(t)
	replayed := assertion
	replayed.RequestID = second.RequestID
	if _, err := fixture.complete(t, second, replayed); !errors.Is(
		err, ErrSAMLAssertionRejected) {
		t.Fatalf("error = %v, want ErrSAMLAssertionRejected", err)
	}
}

// TestSAMLLoginRefusesWhatTheSignatureDoesNotCover walks the refusals a valid
// signature leaves open, and checks each one is opaque outwardly while the
// specific reason reaches the ledger.
func TestSAMLLoginRefusesWhatTheSignatureDoesNotCover(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		mutate func(*samltest.Assertion)
		reason string
	}{
		"another provider's issuer": {
			mutate: func(a *samltest.Assertion) { a.Issuer = "https://evil.example/metadata" },
			reason: "request_mismatch",
		},
		"an assertion written for another service provider": {
			mutate: func(a *samltest.Assertion) { a.Audience = "https://other.example/sp" },
			reason: "audience_mismatch",
		},
		"delivery to a different consumer": {
			mutate: func(a *samltest.Assertion) { a.Recipient = "https://evil.example/acs" },
			reason: "request_mismatch",
		},
		"an answer to somebody else's login": {
			mutate: func(a *samltest.Assertion) { a.RequestID = "_another-login" },
			reason: "request_mismatch",
		},
		"an unsolicited assertion": {
			mutate: func(a *samltest.Assertion) { a.RequestID = "" },
			reason: "request_mismatch",
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fixture := newSAMLFixture(t, federationEmailLinking)
			login := fixture.start(t)
			assertion := fixture.assertion(login)
			testCase.mutate(&assertion)

			if _, err := fixture.complete(t, login, assertion); !errors.Is(
				err, ErrSAMLAssertionRejected) {
				t.Fatalf("error = %v, want ErrSAMLAssertionRejected", err)
			}
			// The caller learned nothing; an operator learns everything.
			assertSAMLFailureReason(t, fixture, testCase.reason)
		})
	}
}

// TestSAMLLoginRefusesATamperedAssertion proves the digest covers content and
// not merely shape, through the application boundary.
func TestSAMLLoginRefusesATamperedAssertion(t *testing.T) {
	t.Parallel()

	fixture := newSAMLFixture(t, federationEmailLinking)
	login := fixture.start(t)
	document, err := fixture.signer.Sign(fixture.assertion(login).Document())
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	tampered := strings.Replace(document, "alice@example.com", "attacker@example.com", 1)

	if _, err := fixture.service.SAMLLoginComplete(context.Background(), fixture.tenantID,
		login.LoginID, []byte(tampered), "test"); !errors.Is(err, ErrSAMLAssertionRejected) {
		t.Fatalf("error = %v, want ErrSAMLAssertionRejected", err)
	}
	assertSAMLFailureReason(t, fixture, "tampered")
}

// TestSAMLLoginRefusesAnotherProvidersSigningKey: a well-formed assertion
// signed by a key this tenant never registered is not this provider speaking.
func TestSAMLLoginRefusesAnotherProvidersSigningKey(t *testing.T) {
	t.Parallel()

	fixture := newSAMLFixture(t, federationEmailLinking)
	attacker, err := samltest.NewSigner("attacker.example")
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	login := fixture.start(t)
	document, err := attacker.Sign(fixture.assertion(login).Document())
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if _, err := fixture.service.SAMLLoginComplete(context.Background(), fixture.tenantID,
		login.LoginID, []byte(document), "test"); !errors.Is(err, ErrSAMLAssertionRejected) {
		t.Fatalf("error = %v, want ErrSAMLAssertionRejected", err)
	}
	assertSAMLFailureReason(t, fixture, "invalid_signature")
}

// TestSAMLLoginAcceptsEitherCertificateDuringARotation: a provider publishes
// the new certificate before it signs with it, so both must verify or every
// rotation is an outage.
func TestSAMLLoginAcceptsEitherCertificateDuringARotation(t *testing.T) {
	t.Parallel()

	fixture := newSAMLFixture(t, federationEmailLinking)
	rotated, err := samltest.NewSigner("idp.example.com")
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	provider, err := fixture.service.SAMLProviderRegister(context.Background(),
		fixture.tenantID, "Corp SSO rotating", "https://idp.example.com/metadata-2",
		samlSSOURL, []string{fixture.signer.PEM, rotated.PEM}, "email",
		federationEmailLinking, "test")
	if err != nil {
		t.Fatalf("SAMLProviderRegister() error = %v", err)
	}

	for name, signer := range map[string]*samltest.Signer{
		"the outgoing certificate": fixture.signer,
		"the incoming certificate": rotated,
	} {
		login, err := fixture.service.SAMLLoginStart(context.Background(),
			fixture.tenantID, provider.ID, samlConsumerURL, "test")
		if err != nil {
			t.Fatalf("%s: SAMLLoginStart() error = %v", name, err)
		}
		assertion := fixture.assertion(login)
		assertion.Issuer = "https://idp.example.com/metadata-2"
		assertion.ID = "_rotation-" + name
		document, err := signer.Sign(assertion.Document())
		if err != nil {
			t.Fatalf("%s: Sign() error = %v", name, err)
		}
		if _, err := fixture.service.SAMLLoginComplete(context.Background(),
			fixture.tenantID, login.LoginID, []byte(document), "test"); err != nil {
			t.Fatalf("%s: SAMLLoginComplete() error = %v", name, err)
		}
	}
}

// TestSAMLLoginExpires: an abandoned transaction must not stay a standing
// target for an assertion obtained later.
func TestSAMLLoginExpires(t *testing.T) {
	t.Parallel()

	fixture := newSAMLFixture(t, federationEmailLinking)
	login := fixture.start(t)
	assertion := fixture.assertion(login)
	fixture.now = fixture.now.Add(samldomain.LoginLifetime + time.Second)
	assertion.NotOnOrAfter = fixture.now.Add(5 * time.Minute)

	if _, err := fixture.complete(t, login, assertion); !errors.Is(err, ErrSAMLLoginNotFound) {
		t.Fatalf("error = %v, want ErrSAMLLoginNotFound", err)
	}
}

// TestSAMLLoginIsSingleUse: a completed transaction cannot be completed again.
func TestSAMLLoginIsSingleUse(t *testing.T) {
	t.Parallel()

	fixture := newSAMLFixture(t, federationEmailLinking)
	login := fixture.start(t)
	if _, err := fixture.complete(t, login, fixture.assertion(login)); err != nil {
		t.Fatalf("SAMLLoginComplete() error = %v", err)
	}
	if _, err := fixture.complete(t, login, fixture.assertion(login)); !errors.Is(
		err, ErrSAMLLoginNotFound) {
		t.Fatalf("error = %v, want ErrSAMLLoginNotFound", err)
	}
}

// TestSAMLProviderDisableIsDurableAndImmediate.
func TestSAMLProviderDisableIsDurableAndImmediate(t *testing.T) {
	t.Parallel()

	fixture := newSAMLFixture(t, federationEmailLinking)
	if err := fixture.service.SAMLProviderDisable(context.Background(), fixture.tenantID,
		fixture.providerID, "contract ended", "test"); err != nil {
		t.Fatalf("SAMLProviderDisable() error = %v", err)
	}
	if _, err := fixture.service.SAMLLoginStart(context.Background(), fixture.tenantID,
		fixture.providerID, samlConsumerURL, "test"); !errors.Is(err, ErrSAMLProviderNotFound) {
		t.Fatalf("error = %v, want ErrSAMLProviderNotFound", err)
	}
	// Disabling twice is a no-op rather than an error: an operator retrying
	// after a timeout must not be told the second attempt failed.
	if err := fixture.service.SAMLProviderDisable(context.Background(), fixture.tenantID,
		fixture.providerID, "contract ended", "test"); err != nil {
		t.Fatalf("second SAMLProviderDisable() error = %v", err)
	}
}

// TestSAMLProviderIsTenantScoped: another tenant must not see, disable, or
// authenticate through this tenant's provider.
func TestSAMLProviderIsTenantScoped(t *testing.T) {
	t.Parallel()

	fixture := newSAMLFixture(t, federationEmailLinking)
	other, err := fixture.service.Bootstrap(context.Background(), "other", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	otherID := other.Tenant.ID

	if _, err := fixture.service.SAMLProviderGet(otherID, fixture.providerID); !errors.Is(
		err, ErrSAMLProviderNotFound) {
		t.Fatalf("SAMLProviderGet() error = %v, want ErrSAMLProviderNotFound", err)
	}
	if _, err := fixture.service.SAMLLoginStart(context.Background(), otherID,
		fixture.providerID, samlConsumerURL, "test"); !errors.Is(err, ErrSAMLProviderNotFound) {
		t.Fatalf("SAMLLoginStart() error = %v, want ErrSAMLProviderNotFound", err)
	}
	if err := fixture.service.SAMLProviderDisable(context.Background(), otherID,
		fixture.providerID, "", "test"); !errors.Is(err, ErrSAMLProviderNotFound) {
		t.Fatalf("SAMLProviderDisable() error = %v, want ErrSAMLProviderNotFound", err)
	}

	login := fixture.start(t)
	if _, err := fixture.service.SAMLLoginComplete(context.Background(), otherID,
		login.LoginID, []byte("<ignored/>"), "test"); !errors.Is(err, ErrSAMLLoginNotFound) {
		t.Fatalf("SAMLLoginComplete() error = %v, want ErrSAMLLoginNotFound", err)
	}
}

// TestSAMLLoginStartRefusesWithoutADeploymentIssuer: without one SESAME
// cannot say who an assertion should be addressed to, so it must not ask for
// one.
func TestSAMLLoginStartRefusesWithoutADeploymentIssuer(t *testing.T) {
	t.Parallel()

	fixture := newSAMLFixture(t, federationEmailLinking)
	fixture.service.UseIssuer("")
	if _, err := fixture.service.SAMLLoginStart(context.Background(), fixture.tenantID,
		fixture.providerID, samlConsumerURL, "test"); !errors.Is(err, ErrNoIssuer) {
		t.Fatalf("error = %v, want ErrNoIssuer", err)
	}
}

// TestSAMLProviderRegisterValidatesItsConfiguration keeps a broken provider
// out of storage rather than failing at somebody's first login.
func TestSAMLProviderRegisterValidatesItsConfiguration(t *testing.T) {
	t.Parallel()

	fixture := newSAMLFixture(t, federationEmailLinking)
	cases := map[string]struct {
		name, entityID, ssoURL string
		certificates           []string
		linking                string
	}{
		"no name": {"", samlEntityID, samlSSOURL, []string{fixture.signer.PEM}, "strict"},
		"entity ID with whitespace": {
			"n", " " + samlEntityID, samlSSOURL, []string{fixture.signer.PEM}, "strict"},
		"plaintext single sign-on URL": {
			"n", samlEntityID, "http://idp.example.com/sso", []string{fixture.signer.PEM}, "strict"},
		"no certificate":      {"n", samlEntityID, samlSSOURL, nil, "strict"},
		"garbage certificate": {"n", samlEntityID, samlSSOURL, []string{"not-a-certificate"}, "strict"},
		"unknown linking policy": {
			"n", samlEntityID, samlSSOURL, []string{fixture.signer.PEM}, "whatever"},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := fixture.service.SAMLProviderRegister(context.Background(),
				fixture.tenantID, testCase.name, testCase.entityID, testCase.ssoURL,
				testCase.certificates, "email", testCase.linking, "test"); err == nil {
				t.Fatal("SAMLProviderRegister accepted a broken configuration")
			}
		})
	}
}

// TestSAMLLoginRefusesASuspendedPrincipal: a linked subject whose principal
// has been suspended must not be able to sign in, however valid the
// assertion. Revocation that a federation can talk past is not revocation.
func TestSAMLLoginRefusesASuspendedPrincipal(t *testing.T) {
	t.Parallel()

	fixture := newSAMLFixture(t, federationEmailLinking)
	login := fixture.start(t)
	result, err := fixture.complete(t, login, fixture.assertion(login))
	if err != nil {
		t.Fatalf("SAMLLoginComplete() error = %v", err)
	}
	if _, err := fixture.service.PrincipalSuspend(context.Background(),
		result.PrincipalID, "test"); err != nil {
		t.Fatalf("PrincipalSuspend() error = %v", err)
	}

	second := fixture.start(t)
	assertion := fixture.assertion(second)
	assertion.ID = "_assertion-after-suspension"
	if _, err := fixture.complete(t, second, assertion); err == nil {
		t.Fatal("a suspended principal signed in through SAML")
	} else if !errors.Is(err, ErrSubjectNotLinked) {
		t.Fatalf("error = %v, want ErrSubjectNotLinked", err)
	}
}

// assertSAMLFailureReason checks the ledger carries the specific reason the
// caller was not told, and that no part of the assertion leaked with it.
func assertSAMLFailureReason(t *testing.T, fixture *samlFixture, reason string) {
	t.Helper()

	for _, event := range fixture.ledger.events {
		if event.Type != samldomain.EventLoginFailed {
			continue
		}
		var payload samldomain.LoginFailedPayload
		if err := decodeStrict(event.Payload, &payload); err != nil {
			t.Fatalf("decode failure payload: %v", err)
		}
		if payload.Reason == reason {
			return
		}
		t.Fatalf("audited reason = %q, want %q", payload.Reason, reason)
	}
	t.Fatalf("no %s event was recorded", samldomain.EventLoginFailed)
}

// TestSnapshotCarriesSAMLState is the regression guard for a snapshot that
// forgets a projection. Three things must survive a restart or the slice is
// unsafe: the provider and its certificates, the subject link, and — most of
// all — the spent-assertion claim. A restart that forgets an assertion was
// used is a restart that makes every captured assertion replayable again.
func TestSnapshotCarriesSAMLState(t *testing.T) {
	t.Parallel()

	fixture := newSAMLFixture(t, federationEmailLinking)
	snapshots := &memorySnapshots{}
	fixture.service.UseSnapshots(snapshots)

	login := fixture.start(t)
	assertion := fixture.assertion(login)
	result, err := fixture.complete(t, login, assertion)
	if err != nil {
		t.Fatalf("SAMLLoginComplete() error = %v", err)
	}

	// A fresh ledger: the restored service must work from snapshot state
	// alone, without replaying the original events.
	restored, err := NewFromSnapshot(&memoryLedger{}, snapshots.states[len(snapshots.states)-1], nil)
	if err != nil {
		t.Fatalf("NewFromSnapshot() error = %v", err)
	}
	restored.UseIssuer(samlAudience)
	restored.UseClock(func() time.Time { return fixture.now })

	provider, err := restored.SAMLProviderGet(fixture.tenantID, fixture.providerID)
	if err != nil {
		t.Fatalf("snapshot-seeded SAMLProviderGet() error = %v", err)
	}
	if provider.EntityID != samlEntityID {
		t.Fatalf("restored entity ID = %q", provider.EntityID)
	}

	next, err := restored.SAMLLoginStart(context.Background(), fixture.tenantID,
		fixture.providerID, samlConsumerURL, "test")
	if err != nil {
		t.Fatalf("snapshot-seeded SAMLLoginStart() error = %v", err)
	}

	// The spent assertion is still spent.
	replayed := assertion
	replayed.RequestID = next.RequestID
	document, err := fixture.signer.Sign(replayed.Document())
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if _, err := restored.SAMLLoginComplete(context.Background(), fixture.tenantID,
		next.LoginID, []byte(document), "test"); !errors.Is(err, ErrSAMLAssertionRejected) {
		t.Fatalf("a restart forgot a spent assertion: err = %v", err)
	}

	// And the subject is still linked to the same principal, not provisioned
	// a second time. The refused attempt closed its own transaction, so this
	// needs a fresh one.
	third, err := restored.SAMLLoginStart(context.Background(), fixture.tenantID,
		fixture.providerID, samlConsumerURL, "test")
	if err != nil {
		t.Fatalf("snapshot-seeded SAMLLoginStart() error = %v", err)
	}
	fresh := assertion
	fresh.ID = "_assertion-after-restart"
	fresh.RequestID = third.RequestID
	document, err = fixture.signer.Sign(fresh.Document())
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	again, err := restored.SAMLLoginComplete(context.Background(), fixture.tenantID,
		third.LoginID, []byte(document), "test")
	if err != nil {
		t.Fatalf("snapshot-seeded SAMLLoginComplete() error = %v", err)
	}
	if again.PrincipalID != result.PrincipalID || again.Provisioned {
		t.Fatalf("restored login resolved to %#v, want the original principal %q",
			again, result.PrincipalID)
	}
}

// TestReplayCarriesSAMLState is the same guarantee through the other door: a
// deployment with no snapshot rebuilds from the ledger alone.
func TestReplayCarriesSAMLState(t *testing.T) {
	t.Parallel()

	fixture := newSAMLFixture(t, federationEmailLinking)
	login := fixture.start(t)
	assertion := fixture.assertion(login)
	if _, err := fixture.complete(t, login, assertion); err != nil {
		t.Fatalf("SAMLLoginComplete() error = %v", err)
	}

	replayed, err := New(&memoryLedger{}, fixture.ledger.events)
	if err != nil {
		t.Fatalf("New() from replay error = %v", err)
	}
	replayed.UseIssuer(samlAudience)
	replayed.UseClock(func() time.Time { return fixture.now })

	next, err := replayed.SAMLLoginStart(context.Background(), fixture.tenantID,
		fixture.providerID, samlConsumerURL, "test")
	if err != nil {
		t.Fatalf("replayed SAMLLoginStart() error = %v", err)
	}
	stale := assertion
	stale.RequestID = next.RequestID
	document, err := fixture.signer.Sign(stale.Document())
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if _, err := replayed.SAMLLoginComplete(context.Background(), fixture.tenantID,
		next.LoginID, []byte(document), "test"); !errors.Is(err, ErrSAMLAssertionRejected) {
		t.Fatalf("a replay forgot a spent assertion: err = %v", err)
	}
}

// TestSAMLRejectionReasonsAreStableAndDistinct pins the audit vocabulary. An
// operator diagnosing a broken provider reads these; a caller never does, so
// they may be specific — but they must not collapse into each other, or the
// diagnosis is worthless.
func TestSAMLRejectionReasonsAreStableAndDistinct(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}
	for _, mapping := range samlRejectionReasons {
		if reason := samlRejectionReason(fmt.Errorf("wrapped: %w", mapping.sentinel)); reason != mapping.reason {
			t.Fatalf("%v mapped to %q, want %q", mapping.sentinel, reason, mapping.reason)
		}
		if seen[mapping.reason] {
			t.Fatalf("two failures share the reason %q", mapping.reason)
		}
		seen[mapping.reason] = true
	}
	// Anything unrecognised must still produce a code, never an empty one.
	if reason := samlRejectionReason(errors.New("something else")); reason != "invalid_assertion" {
		t.Fatalf("unrecognised failure mapped to %q", reason)
	}
}
