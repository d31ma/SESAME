package identity

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	authndomain "github.com/d31ma/sesame/internal/domain/authentication"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	samldomain "github.com/d31ma/sesame/internal/domain/saml"
	sessiondomain "github.com/d31ma/sesame/internal/domain/session"
)

// Stable SAML errors.
var (
	// ErrSAMLProviderNotFound covers unknown, disabled, and cross-tenant
	// providers alike.
	ErrSAMLProviderNotFound = errors.New("SAML identity provider not found")
	// ErrSAMLLoginNotFound covers unknown and cross-tenant logins.
	ErrSAMLLoginNotFound = errors.New("SAML login not found")
	// ErrSAMLAssertionRejected is the single outward reason for every failed
	// assertion, for the same reason federation has one: a caller who can
	// tell "bad signature" from "wrong audience" learns the flow.
	ErrSAMLAssertionRejected = errors.New("the SAML assertion was rejected")
	// ErrSAMLSubjectNotLinked reports a verified assertion for a subject no
	// principal claims, under strict linking.
	ErrSAMLSubjectNotLinked = errors.New("no principal is linked to this SAML subject")
)

// samlProvider is a registered provider plus its parsed certificates.
type samlProvider struct {
	Provider     samldomain.Provider
	Certificates []*x509.Certificate
}

// SAMLLogin is what a caller needs to send a browser to the provider.
type SAMLLogin struct {
	LoginID      string `json:"login_id"`
	RequestID    string `json:"request_id"`
	AuthnRequest string `json:"authn_request"`
	// RedirectURL is the AuthnRequest already encoded for the HTTP-Redirect
	// binding. The host redirects a browser here and needs to know nothing
	// about the binding to do it.
	RedirectURL string `json:"redirect_url"`
	Destination string `json:"destination"`
	ExpiresAt   string `json:"expires_at"`
}

// SAMLSession is the outcome of a completed SAML login.
type SAMLSession struct {
	Session     IssuedSession `json:"session"`
	PrincipalID string        `json:"principal_id"`
	Provisioned bool          `json:"provisioned,omitempty"`
}

// SAMLProviderRegister records an external identity provider.
func (s *Service) SAMLProviderRegister(
	ctx context.Context,
	tenantID, name, entityID, ssoURL string,
	certificates []string,
	namespace, linking, actor string,
) (samldomain.Provider, error) {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return samldomain.Provider{}, err
	}
	request, err := validateSAMLRegistration(name, entityID, ssoURL, certificates,
		namespace, linking)
	if err != nil {
		return samldomain.Provider{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[tenantID]; !exists {
		return samldomain.Provider{}, ErrNotFound
	}
	return s.recordSAMLProviderLocked(ctx, tenantID, request, actor)
}

// samlRegistration is the validated form of a registration request.
type samlRegistration struct {
	Name         string
	EntityID     string
	SSOURL       string
	Certificates []string
	Namespace    string
	Linking      string
}

func validateSAMLRegistration(
	name, entityID, ssoURL string,
	certificates []string,
	namespace, linking string,
) (samlRegistration, error) {
	if err := samldomain.ValidateName(name); err != nil {
		return samlRegistration{}, err
	}
	if err := samldomain.ValidateEntityID(entityID); err != nil {
		return samlRegistration{}, err
	}
	if err := samldomain.ValidateSSOURL(ssoURL); err != nil {
		return samlRegistration{}, err
	}
	// Parsed here so a bad certificate is refused at registration rather than
	// at somebody's first login.
	if _, err := samldomain.ParseCertificates(certificates); err != nil {
		return samlRegistration{}, err
	}
	resolved, err := resolveSAMLLinking(namespace, linking)
	if err != nil {
		return samlRegistration{}, err
	}
	return samlRegistration{
		Name: name, EntityID: entityID, SSOURL: ssoURL,
		Certificates: certificates,
		Namespace:    resolved.namespace, Linking: resolved.linking,
	}, nil
}

type samlLinkingChoice struct {
	namespace string
	linking   string
}

func resolveSAMLLinking(namespace, linking string) (samlLinkingChoice, error) {
	if linking == "" {
		linking = federationStrictLinking
	}
	if linking != federationStrictLinking && linking != federationEmailLinking {
		return samlLinkingChoice{}, fmt.Errorf("linking must be %q or %q",
			federationStrictLinking, federationEmailLinking)
	}
	if namespace == "" {
		namespace = "email"
	}
	return samlLinkingChoice{namespace: namespace, linking: linking}, nil
}

// federationStrictLinking and federationEmailLinking mirror the federation
// slice's policies, so an operator configuring both surfaces meets one
// vocabulary rather than two.
const (
	federationStrictLinking = "strict"
	federationEmailLinking  = "verified_email"
)

func (s *Service) recordSAMLProviderLocked(
	ctx context.Context,
	tenantID string,
	request samlRegistration,
	actor string,
) (samldomain.Provider, error) {
	providerID, err := samldomain.NewProviderID()
	if err != nil {
		return samldomain.Provider{}, err
	}
	event, err := s.ledger.Append(ctx, samldomain.EventProviderRegistered, tenantID, actor,
		samldomain.ProviderRegisteredPayload{
			ProviderID:          providerID,
			TenantID:            tenantID,
			Name:                request.Name,
			EntityID:            request.EntityID,
			SSOURL:              request.SSOURL,
			Certificates:        request.Certificates,
			IdentifierNamespace: request.Namespace,
			Linking:             request.Linking,
		})
	if err != nil {
		return samldomain.Provider{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applySAMLProviderRegistered(event); err != nil {
		return samldomain.Provider{}, err
	}
	s.writeSnapshotLocked(ctx, providerID)
	return s.samlProviders[providerID].Provider, nil
}

// SAMLProviderDisable durably stops new logins through one provider.
func (s *Service) SAMLProviderDisable(
	ctx context.Context,
	tenantID, providerID, reason, actor string,
) error {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return err
	}
	if err := samldomain.ValidateProviderID(providerID); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, exists := s.samlProviders[providerID]
	if !exists || stored.Provider.TenantID != tenantID {
		return ErrSAMLProviderNotFound
	}
	if stored.Provider.Disabled {
		return nil
	}
	return s.appendSAMLProviderDisabled(ctx, tenantID, providerID, reason, actor)
}

func (s *Service) appendSAMLProviderDisabled(
	ctx context.Context,
	tenantID, providerID, reason, actor string,
) error {
	event, err := s.ledger.Append(ctx, samldomain.EventProviderDisabled, tenantID, actor,
		samldomain.ProviderDisabledPayload{
			ProviderID: providerID, TenantID: tenantID, Reason: reason,
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applySAMLProviderDisabled(event); err != nil {
		return err
	}
	s.writeSnapshotLocked(ctx, providerID)
	return nil
}

// SAMLProviderGet reports one provider within its tenant.
func (s *Service) SAMLProviderGet(tenantID, providerID string) (samldomain.Provider, error) {
	if err := samldomain.ValidateProviderID(providerID); err != nil {
		return samldomain.Provider{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, err := s.usableSAMLProviderLocked(tenantID, providerID)
	if err != nil {
		return samldomain.Provider{}, err
	}
	return stored.Provider, nil
}

func (s *Service) usableSAMLProviderLocked(
	tenantID, providerID string,
) (samlProvider, error) {
	stored, exists := s.samlProviders[providerID]
	if !exists || stored.Provider.Disabled || stored.Provider.TenantID != tenantID {
		return samlProvider{}, ErrSAMLProviderNotFound
	}
	return stored, nil
}

// SAMLLoginStart opens a login and returns the AuthnRequest to send.
func (s *Service) SAMLLoginStart(
	ctx context.Context,
	tenantID, providerID, consumerURL, actor string,
) (SAMLLogin, error) {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return SAMLLogin{}, err
	}
	if err := samldomain.ValidateProviderID(providerID); err != nil {
		return SAMLLogin{}, err
	}
	// The deployment issuer is SESAME's SAML entity ID: it names SESAME in
	// the AuthnRequest and is the Audience every assertion must carry. A
	// login started without one would ask a provider to vouch for nobody in
	// particular, so it fails closed rather than defaulting.
	if s.issuer == "" {
		return SAMLLogin{}, ErrNoIssuer
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, err := s.usableSAMLProviderLocked(tenantID, providerID)
	if err != nil {
		return SAMLLogin{}, err
	}
	return s.openSAMLLoginLocked(ctx, stored, consumerURL, actor)
}

func (s *Service) openSAMLLoginLocked(
	ctx context.Context,
	stored samlProvider,
	consumerURL, actor string,
) (SAMLLogin, error) {
	loginID, err := samldomain.NewLoginID()
	if err != nil {
		return SAMLLogin{}, err
	}
	requestID, err := samldomain.NewRequestID()
	if err != nil {
		return SAMLLogin{}, err
	}
	now := s.now()
	expiresAt := now.Add(samldomain.LoginLifetime)
	authnRequest := samldomain.AuthnRequest(requestID, s.issuer,
		stored.Provider.SSOURL, consumerURL, now)
	// Built before the event is appended: a login that cannot be encoded is
	// a login the host cannot use, and recording it would leave a
	// transaction nobody can complete.
	redirectURL, err := samldomain.RedirectURL(stored.Provider.SSOURL, authnRequest, loginID)
	if err != nil {
		return SAMLLogin{}, err
	}
	if err := s.appendSAMLLoginStarted(ctx, loginID, requestID, stored,
		consumerURL, now, expiresAt, actor); err != nil {
		return SAMLLogin{}, err
	}
	s.writeSnapshotLocked(ctx, loginID)
	return SAMLLogin{
		LoginID:      loginID,
		RequestID:    requestID,
		AuthnRequest: authnRequest,
		RedirectURL:  redirectURL,
		Destination:  stored.Provider.SSOURL,
		ExpiresAt:    expiresAt.Format(time.RFC3339Nano),
	}, nil
}

func (s *Service) appendSAMLLoginStarted(
	ctx context.Context,
	loginID, requestID string,
	stored samlProvider,
	consumerURL string,
	now, expiresAt time.Time,
	actor string,
) error {
	event, err := s.ledger.Append(ctx, samldomain.EventLoginStarted,
		stored.Provider.TenantID, actor,
		samldomain.LoginStartedPayload{
			LoginID:    loginID,
			TenantID:   stored.Provider.TenantID,
			ProviderID: stored.Provider.ID,
			RequestID:  requestID,
			Recipient:  consumerURL,
			CreatedAt:  now.Format(time.RFC3339Nano),
			ExpiresAt:  expiresAt.Format(time.RFC3339Nano),
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	return s.applySAMLLoginStarted(event)
}

// SAMLLoginComplete verifies an assertion and issues a session.
//
// Verification, condition checks, and replay all happen before anything is
// created. The document arrives as bytes the host received; SESAME parses and
// verifies it, and the host is never asked to have understood it.
func (s *Service) SAMLLoginComplete(
	ctx context.Context,
	tenantID, loginID string,
	document []byte,
	actor string,
) (SAMLSession, error) {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return SAMLSession{}, err
	}
	if err := samldomain.ValidateLoginID(loginID); err != nil {
		return SAMLSession{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	login, stored, err := s.pendingSAMLLoginLocked(tenantID, loginID)
	if err != nil {
		return SAMLSession{}, err
	}
	assertion, err := s.verifySAMLLocked(ctx, login, stored, document, actor)
	if err != nil {
		return SAMLSession{}, err
	}
	return s.completeSAMLLoginLocked(ctx, login, stored, assertion, actor)
}

// pendingSAMLLoginLocked resolves a usable login and its provider.
func (s *Service) pendingSAMLLoginLocked(
	tenantID, loginID string,
) (samlLogin, samlProvider, error) {
	login, exists := s.samlLogins[loginID]
	if !exists || login.TenantID != tenantID {
		return samlLogin{}, samlProvider{}, ErrSAMLLoginNotFound
	}
	if login.Status != samlLoginPending {
		return samlLogin{}, samlProvider{}, ErrSAMLLoginNotFound
	}
	if !s.now().Before(login.ExpiresAt) {
		return samlLogin{}, samlProvider{}, ErrSAMLLoginNotFound
	}
	stored, err := s.usableSAMLProviderLocked(tenantID, login.ProviderID)
	if err != nil {
		return samlLogin{}, samlProvider{}, err
	}
	return login, stored, nil
}

// verifySAMLLocked verifies the signature and every condition, auditing a
// rejection with its specific reason while returning an opaque one.
func (s *Service) verifySAMLLocked(
	ctx context.Context,
	login samlLogin,
	stored samlProvider,
	document []byte,
	actor string,
) (samldomain.Assertion, error) {
	assertion, err := s.checkSAMLAssertion(login, stored, document)
	if err != nil {
		s.failSAMLLoginLocked(ctx, login, samlRejectionReason(err), actor)
		return samldomain.Assertion{}, ErrSAMLAssertionRejected
	}
	// Single use. A restart cannot forget this: the replay key is recorded in
	// the completion event and replays into the projection.
	if _, spent := s.samlReplay[samldomain.ReplayKey(
		stored.Provider.EntityID, assertion.ID)]; spent {
		s.failSAMLLoginLocked(ctx, login, "replayed", actor)
		return samldomain.Assertion{}, ErrSAMLAssertionRejected
	}
	return assertion, nil
}

// checkSAMLAssertion runs verification against every accepted certificate.
//
// More than one is normal during a rotation: the provider publishes the new
// certificate before signing with it, so both must verify until the old one
// is withdrawn.
func (s *Service) checkSAMLAssertion(
	login samlLogin,
	stored samlProvider,
	document []byte,
) (samldomain.Assertion, error) {
	var lastErr error
	for _, certificate := range stored.Certificates {
		signed, err := samldomain.Verify(document, certificate)
		if err != nil {
			lastErr = err
			continue
		}
		assertion, err := samldomain.ParseAssertion(signed)
		if err != nil {
			return samldomain.Assertion{}, err
		}
		return assertion, assertion.Check(samldomain.Expectation{
			Issuer:    stored.Provider.EntityID,
			Audience:  s.issuer,
			Recipient: login.Recipient,
			RequestID: login.RequestID,
			Now:       s.now(),
		})
	}
	if lastErr == nil {
		lastErr = samldomain.ErrSignatureInvalid
	}
	return samldomain.Assertion{}, lastErr
}

// samlRejectionReasons maps a domain failure to a stable audit code.
//
// A table rather than a chain of errors.Is calls: adding a case is one line
// and does not make the mapping harder to reason about, the same shape the
// federation slice uses on the wire.
var samlRejectionReasons = []struct {
	sentinel error
	reason   string
}{
	{samldomain.ErrAmbiguous, "ambiguous_document"},
	{samldomain.ErrNoSignature, "unsigned"},
	{samldomain.ErrDigestMismatch, "tampered"},
	{samldomain.ErrSignatureInvalid, "invalid_signature"},
	{samldomain.ErrUnsupportedAlgorithm, "unsupported_algorithm"},
	{samldomain.ErrAssertionExpired, "expired"},
	{samldomain.ErrAudienceMismatch, "audience_mismatch"},
	{samldomain.ErrRequestMismatch, "request_mismatch"},
	{samldomain.ErrSubjectUnusable, "unusable_subject"},
}

// samlRejectionReason resolves the audit code for a failure. The caller never
// sees it; an operator diagnosing a broken provider does.
func samlRejectionReason(err error) string {
	for _, mapping := range samlRejectionReasons {
		if errors.Is(err, mapping.sentinel) {
			return mapping.reason
		}
	}
	return "invalid_assertion"
}

func (s *Service) failSAMLLoginLocked(
	ctx context.Context,
	login samlLogin,
	reason, actor string,
) {
	event, err := s.ledger.Append(ctx, samldomain.EventLoginFailed, login.TenantID, actor,
		samldomain.LoginFailedPayload{
			LoginID:    login.ID,
			TenantID:   login.TenantID,
			ProviderID: login.ProviderID,
			Reason:     reason,
			FailedAt:   s.now().Format(time.RFC3339Nano),
		})
	if err != nil {
		s.logger.ErrorContext(ctx, "recording a SAML login failure failed",
			"login_id", login.ID, "error", err)
		return
	}
	if err := s.applySAMLLoginFailed(event); err != nil {
		s.logger.ErrorContext(ctx, "applying a SAML login failure failed",
			"login_id", login.ID, "error", err)
	}
}

// completeSAMLLoginLocked resolves the principal and issues the session.
func (s *Service) completeSAMLLoginLocked(
	ctx context.Context,
	login samlLogin,
	stored samlProvider,
	assertion samldomain.Assertion,
	actor string,
) (SAMLSession, error) {
	hash := samlSubjectHash(stored.Provider.ID, assertion.Subject)
	principalID, provisioned, err := s.resolveSAMLPrincipalLocked(ctx, stored, assertion, hash, actor)
	if err != nil {
		return SAMLSession{}, err
	}
	session, err := s.issueSAMLSessionLocked(ctx, login, principalID, actor)
	if err != nil {
		return SAMLSession{}, err
	}
	if err := s.appendSAMLLoginCompleted(ctx, login, stored, assertion,
		principalID, hash, provisioned, actor); err != nil {
		return SAMLSession{}, err
	}
	s.writeSnapshotLocked(ctx, login.ID)
	return SAMLSession{Session: session, PrincipalID: principalID, Provisioned: provisioned}, nil
}

// resolveSAMLPrincipalLocked finds or creates the principal a subject means.
func (s *Service) resolveSAMLPrincipalLocked(
	ctx context.Context,
	stored samlProvider,
	assertion samldomain.Assertion,
	hash, actor string,
) (string, bool, error) {
	if principalID, linked := s.samlLinks[hash]; linked {
		return principalID, false, s.checkPrincipalActiveLocked(principalID)
	}
	if stored.Provider.Linking == federationStrictLinking {
		return "", false, ErrSAMLSubjectNotLinked
	}
	return s.provisionSAMLPrincipalLocked(ctx, stored, assertion, actor)
}

// provisionSAMLPrincipalLocked matches or creates a principal from the
// subject, which under verified-email linking is the NameID itself.
//
// Unlike OIDC there is no `email_verified` claim to consult: SAML has no
// equivalent, and the provider asserting a NameID *is* the assertion. That
// makes the choice of provider the whole trust decision, which is why
// verified-email linking is opt-in per provider rather than the default.
func (s *Service) provisionSAMLPrincipalLocked(
	ctx context.Context,
	stored samlProvider,
	assertion samldomain.Assertion,
	actor string,
) (string, bool, error) {
	value := principaldomain.NormalizeIdentifier(assertion.Subject)
	key := identifierKey(stored.Provider.TenantID, stored.Provider.IdentifierNamespace, value)
	if principalID, claimed := s.identifiers[key]; claimed {
		return principalID, false, s.checkPrincipalActiveLocked(principalID)
	}
	identifier := principaldomain.Identifier{
		Namespace: stored.Provider.IdentifierNamespace, Value: value,
	}
	if err := principaldomain.ValidateIdentifier(identifier); err != nil {
		return "", false, err
	}
	principalID, err := principaldomain.NewID()
	if err != nil {
		return "", false, err
	}
	if err := s.appendPrincipalForSAML(ctx, stored, principalID, identifier, actor); err != nil {
		return "", false, err
	}
	return principalID, true, nil
}

func (s *Service) appendPrincipalForSAML(
	ctx context.Context,
	stored samlProvider,
	principalID string,
	identifier principaldomain.Identifier,
	actor string,
) error {
	event, err := s.ledger.Append(ctx, principaldomain.EventCreated,
		stored.Provider.TenantID, actor,
		principaldomain.CreatedPayload{
			PrincipalID:         principalID,
			TenantID:            stored.Provider.TenantID,
			Kind:                principaldomain.KindHuman,
			Status:              principaldomain.StatusActive,
			IdentifierNamespace: identifier.Namespace,
			IdentifierValue:     identifier.Value,
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	return s.applyPrincipalCreated(event)
}

// issueSAMLSessionLocked mints the session at federated assurance, for the
// same reason inbound OIDC does: SESAME did not witness the credential.
func (s *Service) issueSAMLSessionLocked(
	ctx context.Context,
	login samlLogin,
	principalID, actor string,
) (IssuedSession, error) {
	sessionID, err := sessiondomain.NewID()
	if err != nil {
		return IssuedSession{}, err
	}
	secret, digest, err := sessiondomain.NewSecret()
	if err != nil {
		return IssuedSession{}, err
	}
	now := s.now()
	expiresAt := now.Add(sessiondomain.DefaultLifetime).Format(time.RFC3339Nano)
	event, err := s.ledger.Append(ctx, sessiondomain.EventIssued, login.TenantID, actor,
		sessiondomain.IssuedPayload{
			SessionID:    sessionID,
			TenantID:     login.TenantID,
			PrincipalID:  principalID,
			IssuedAt:     now.Format(time.RFC3339Nano),
			ExpiresAt:    expiresAt,
			SecretDigest: digest,
			Assurance:    authndomain.AssuranceFederated,
		})
	if err != nil {
		return IssuedSession{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applySessionIssued(event); err != nil {
		return IssuedSession{}, err
	}
	return IssuedSession{
		SessionID:   sessionID,
		Secret:      secret,
		TenantID:    login.TenantID,
		PrincipalID: principalID,
		ExpiresAt:   expiresAt,
		Assurance:   authndomain.AssuranceFederated,
	}, nil
}

func (s *Service) appendSAMLLoginCompleted(
	ctx context.Context,
	login samlLogin,
	stored samlProvider,
	assertion samldomain.Assertion,
	principalID, hash string,
	provisioned bool,
	actor string,
) error {
	event, err := s.ledger.Append(ctx, samldomain.EventLoginCompleted, login.TenantID, actor,
		samldomain.LoginCompletedPayload{
			LoginID:     login.ID,
			TenantID:    login.TenantID,
			ProviderID:  login.ProviderID,
			PrincipalID: principalID,
			SubjectHash: hash,
			ReplayKey:   samldomain.ReplayKey(stored.Provider.EntityID, assertion.ID),
			Provisioned: provisioned,
			CompletedAt: s.now().Format(time.RFC3339Nano),
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	return s.applySAMLLoginCompleted(event)
}

// samlSubjectHash binds a subject to its provider, length-prefixed for the
// same reason federation's is: a separator alone is ambiguous.
func samlSubjectHash(providerID, subject string) string {
	return samldomain.ReplayKey(providerID, subject)
}
