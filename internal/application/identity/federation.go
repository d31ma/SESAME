package identity

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	authndomain "github.com/d31ma/sesame/internal/domain/authentication"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	federationdomain "github.com/d31ma/sesame/internal/domain/federation"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	sessiondomain "github.com/d31ma/sesame/internal/domain/session"
)

// Stable federation errors.
var (
	// ErrProviderNotFound covers unknown, disabled, and cross-tenant
	// providers alike. Telling them apart would confirm which providers a
	// neighbouring tenant has registered.
	ErrProviderNotFound = errors.New("identity provider not found")
	// ErrProviderNotConfigured reports a provider whose discovery document
	// has not been supplied yet, so SESAME does not know its endpoints.
	ErrProviderNotConfigured = errors.New("identity provider has no validated metadata")
	// ErrFederatedLoginNotFound covers unknown and cross-tenant logins.
	ErrFederatedLoginNotFound = errors.New("federated login not found")
	// ErrSubjectNotLinked reports a verified assertion for an external
	// subject that no principal claims, under strict linking.
	ErrSubjectNotLinked = errors.New("no principal is linked to this external subject")
	// ErrAssertionRejected is the single outward reason for every failed
	// assertion. The specific cause is audited, never returned: a caller who
	// can tell "wrong nonce" from "unknown key" learns about the flow.
	ErrAssertionRejected = errors.New("the provider's assertion was rejected")
)

// federationProvider is a registered provider plus what SESAME has learned
// about it. Metadata and keys are derived, refetchable, and never
// authoritative over the registered issuer.
type federationProvider struct {
	Provider     federationdomain.Provider
	SecretSealed string
	Metadata     federationdomain.Metadata
	Keys         federationdomain.KeySet
	Configured   bool
}

// FetchInstruction is what the engine asks the host to retrieve. The URL is
// always derived from a registered issuer, never from a caller, which is what
// keeps SSRF structurally absent rather than filtered.
type FetchInstruction struct {
	URL    string            `json:"url"`
	Method string            `json:"method"`
	Form   map[string]string `json:"form,omitempty"`
}

// FederatedLogin is what a caller needs to send a browser to the provider.
type FederatedLogin struct {
	LoginID          string `json:"login_id"`
	AuthorizationURL string `json:"authorization_url"`
	ExpiresAt        string `json:"expires_at"`
}

// providerRegistration is the validated form of a registration request. It
// exists so ProviderRegister stays a short sequence of steps rather than a
// long chain of guards.
type providerRegistration struct {
	Name         string
	Issuer       string
	ClientID     string
	Scopes       []string
	SubjectClaim string
	EmailClaim   string
	Linking      string
}

// validateProviderRegistration checks every operator-supplied field.
func validateProviderRegistration(
	name, issuer, clientID string,
	scopes []string,
	subjectClaim, emailClaim, linking string,
) (providerRegistration, error) {
	normalizedIssuer, err := federationdomain.NormalizeIssuer(issuer)
	if err != nil {
		return providerRegistration{}, err
	}
	normalizedScopes, err := federationdomain.NormalizeScopes(scopes)
	if err != nil {
		return providerRegistration{}, err
	}
	claims, err := validateClaimNames(subjectClaim, emailClaim, linking)
	if err != nil {
		return providerRegistration{}, err
	}
	if err := checkProviderIdentity(name, clientID); err != nil {
		return providerRegistration{}, err
	}
	return providerRegistration{
		Name:         name,
		Issuer:       normalizedIssuer,
		ClientID:     clientID,
		Scopes:       normalizedScopes,
		SubjectClaim: claims.subject,
		EmailClaim:   claims.email,
		Linking:      claims.linking,
	}, nil
}

type claimNames struct {
	subject string
	email   string
	linking string
}

// validateClaimNames applies the defaults and the linking policy together,
// because verified-email linking is meaningless without an email claim.
func validateClaimNames(subjectClaim, emailClaim, linking string) (claimNames, error) {
	if subjectClaim == "" {
		subjectClaim = "sub"
	}
	if linking == "" {
		linking = federationdomain.LinkingStrict
	}
	if err := federationdomain.ValidateClaimName(subjectClaim); err != nil {
		return claimNames{}, err
	}
	if err := federationdomain.ValidateLinking(linking); err != nil {
		return claimNames{}, err
	}
	return claimNames{subject: subjectClaim, email: emailClaim, linking: linking},
		checkEmailClaim(emailClaim, linking)
}

// checkEmailClaim refuses a configuration that could never work: linking on a
// verified email with no claim to read it from would fail every login, and
// failing at registration says so once instead of at every attempt.
func checkEmailClaim(emailClaim, linking string) error {
	if linking != federationdomain.LinkingVerifiedEmail {
		return nil
	}
	if emailClaim == "" {
		return errors.New("verified-email linking requires an email claim name")
	}
	return federationdomain.ValidateClaimName(emailClaim)
}

func checkProviderIdentity(name, clientID string) error {
	if err := federationdomain.ValidateName(name); err != nil {
		return err
	}
	if clientID == "" || len(clientID) > 512 {
		return errors.New("the provider's client identifier is required")
	}
	return nil
}

// ProviderRegister records an external OpenID Provider for one tenant.
//
// The returned instruction is the discovery fetch the host must perform
// before the provider can be used. SESAME builds that URL from the registered
// issuer, so the host is never handed an address a caller chose.
func (s *Service) ProviderRegister(
	ctx context.Context,
	tenantID, name, issuer, clientID, clientSecret string,
	scopes []string,
	subjectClaim, emailClaim, linking, actor string,
) (federationdomain.Provider, FetchInstruction, error) {
	request, err := validateProviderRegistration(
		name, issuer, clientID, scopes, subjectClaim, emailClaim, linking)
	if err != nil {
		return federationdomain.Provider{}, FetchInstruction{}, err
	}
	if err := s.requireLedgerAndActor(actor); err != nil {
		return federationdomain.Provider{}, FetchInstruction{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	provider, err := s.recordProviderLocked(ctx, tenantID, request, clientSecret, actor)
	if err != nil {
		return federationdomain.Provider{}, FetchInstruction{}, err
	}
	return provider, DiscoveryInstruction(request.Issuer), nil
}

// DiscoveryInstruction names the well-known document for an issuer.
func DiscoveryInstruction(issuer string) FetchInstruction {
	return FetchInstruction{
		URL:    issuer + federationdomain.DiscoveryPath,
		Method: "GET",
	}
}

func (s *Service) requireLedgerAndActor(actor string) error {
	if err := s.requireLedger(); err != nil {
		return err
	}
	if actor == "" {
		return errors.New("actor is required")
	}
	return nil
}

// recordProviderLocked seals the client secret and appends the registration.
func (s *Service) recordProviderLocked(
	ctx context.Context,
	tenantID string,
	request providerRegistration,
	clientSecret, actor string,
) (federationdomain.Provider, error) {
	if _, exists := s.byID[tenantID]; !exists {
		return federationdomain.Provider{}, ErrNotFound
	}
	providerID, sealed, err := s.newProviderIdentity(clientSecret)
	if err != nil {
		return federationdomain.Provider{}, err
	}
	event, err := s.ledger.Append(ctx, federationdomain.EventProviderRegistered, tenantID, actor,
		federationdomain.ProviderRegisteredPayload{
			ProviderID:   providerID,
			TenantID:     tenantID,
			Name:         request.Name,
			Issuer:       request.Issuer,
			ClientID:     request.ClientID,
			Scopes:       request.Scopes,
			SubjectClaim: request.SubjectClaim,
			EmailClaim:   request.EmailClaim,
			Linking:      request.Linking,
			SecretSealed: sealed,
		})
	if err != nil {
		return federationdomain.Provider{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyProviderRegistered(event); err != nil {
		return federationdomain.Provider{}, err
	}
	s.writeSnapshotLocked(ctx, providerID)
	return s.providers[providerID].Provider, nil
}

// sealProviderSecret encrypts rather than hashes: unlike a SESAME client
// secret, this one must be replayed to the provider's token endpoint on every
// exchange, so it has to be recoverable.
func (s *Service) sealProviderSecret(clientSecret string) (string, error) {
	if clientSecret == "" {
		return "", nil
	}
	return authenticatordomain.Seal(s.secretsKey, clientSecret)
}

// ProviderConfigure validates a fetched discovery document and key set, and
// records what SESAME will act on.
//
// Both documents are adversarial input. Everything they claim is checked
// against the registered issuer before any of it is stored.
func (s *Service) ProviderConfigure(
	ctx context.Context,
	tenantID, providerID string,
	discoveryDocument, keySetDocument []byte,
	actor string,
) (federationdomain.Metadata, error) {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return federationdomain.Metadata{}, err
	}
	if err := federationdomain.ValidateProviderID(providerID); err != nil {
		return federationdomain.Metadata{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, err := s.usableProviderLocked(tenantID, providerID)
	if err != nil {
		return federationdomain.Metadata{}, err
	}
	metadata, keys, err := parseProviderDocuments(
		stored.Provider.Issuer, discoveryDocument, keySetDocument)
	if err != nil {
		return federationdomain.Metadata{}, err
	}
	stored.Metadata = metadata
	stored.Keys = keys
	stored.Configured = true
	s.providers[providerID] = stored
	return metadata, nil
}

// parseProviderDocuments keeps the two untrusted parses together so neither
// can be skipped by a caller that only supplies one.
func parseProviderDocuments(
	issuer string,
	discoveryDocument, keySetDocument []byte,
) (federationdomain.Metadata, federationdomain.KeySet, error) {
	metadata, err := federationdomain.ParseMetadata(issuer, discoveryDocument)
	if err != nil {
		return federationdomain.Metadata{}, federationdomain.KeySet{}, err
	}
	keys, err := federationdomain.ParseKeySet(keySetDocument)
	if err != nil {
		return federationdomain.Metadata{}, federationdomain.KeySet{}, err
	}
	return metadata, keys, nil
}

// usableProviderLocked resolves a provider within its tenant.
func (s *Service) usableProviderLocked(
	tenantID, providerID string,
) (federationProvider, error) {
	stored, exists := s.providers[providerID]
	if !exists || stored.Provider.Disabled {
		return federationProvider{}, ErrProviderNotFound
	}
	if stored.Provider.TenantID != tenantID {
		return federationProvider{}, ErrProviderNotFound
	}
	return stored, nil
}

// LoginStart opens a federated login and returns the URL to send the browser
// to.
func (s *Service) LoginStart(
	ctx context.Context,
	tenantID, providerID, redirectURI, actor string,
) (FederatedLogin, error) {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return FederatedLogin{}, err
	}
	if err := federationdomain.ValidateProviderID(providerID); err != nil {
		return FederatedLogin{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, err := s.configuredProviderLocked(tenantID, providerID)
	if err != nil {
		return FederatedLogin{}, err
	}
	return s.openLoginLocked(ctx, stored, redirectURI, actor)
}

func (s *Service) configuredProviderLocked(
	tenantID, providerID string,
) (federationProvider, error) {
	stored, err := s.usableProviderLocked(tenantID, providerID)
	if err != nil {
		return federationProvider{}, err
	}
	if !stored.Configured {
		return federationProvider{}, ErrProviderNotConfigured
	}
	return stored, nil
}

// loginSecrets are the three unguessable values one federated login needs.
type loginSecrets struct {
	state    string
	nonce    string
	verifier string
}

func newLoginSecrets() (loginSecrets, error) {
	state, err := federationdomain.NewState()
	if err != nil {
		return loginSecrets{}, err
	}
	nonce, err := federationdomain.NewNonce()
	if err != nil {
		return loginSecrets{}, err
	}
	verifier, err := federationdomain.NewVerifier()
	if err != nil {
		return loginSecrets{}, err
	}
	return loginSecrets{state: state, nonce: nonce, verifier: verifier}, nil
}

// openLoginLocked persists the transaction and builds the authorization URL.
func (s *Service) openLoginLocked(
	ctx context.Context,
	stored federationProvider,
	redirectURI, actor string,
) (FederatedLogin, error) {
	loginID, err := federationdomain.NewLoginID()
	if err != nil {
		return FederatedLogin{}, err
	}
	secrets, err := newLoginSecrets()
	if err != nil {
		return FederatedLogin{}, err
	}
	sealed, err := authenticatordomain.Seal(s.secretsKey, encodeLoginSecrets(secrets))
	if err != nil {
		return FederatedLogin{}, err
	}
	now := s.now()
	if err := s.appendLoginStarted(ctx, loginID, stored, secrets, sealed, redirectURI, now, actor); err != nil {
		return FederatedLogin{}, err
	}
	s.writeSnapshotLocked(ctx, loginID)
	return FederatedLogin{
		LoginID:          loginID,
		AuthorizationURL: authorizationURL(stored, secrets, redirectURI),
		ExpiresAt:        now.Add(federationdomain.LoginLifetime).Format(time.RFC3339Nano),
	}, nil
}

func (s *Service) appendLoginStarted(
	ctx context.Context,
	loginID string,
	stored federationProvider,
	secrets loginSecrets,
	sealed, redirectURI string,
	now time.Time,
	actor string,
) error {
	event, err := s.ledger.Append(ctx, federationdomain.EventLoginStarted,
		stored.Provider.TenantID, actor,
		federationdomain.LoginStartedPayload{
			LoginID:       loginID,
			TenantID:      stored.Provider.TenantID,
			ProviderID:    stored.Provider.ID,
			StateDigest:   federationdomain.Digest(secrets.state),
			NonceDigest:   federationdomain.Digest(secrets.nonce),
			RedirectURI:   redirectURI,
			CreatedAt:     now.Format(time.RFC3339Nano),
			ExpiresAt:     now.Add(federationdomain.LoginLifetime).Format(time.RFC3339Nano),
			SecretsSealed: sealed,
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	return s.applyLoginStarted(event)
}

// encodeLoginSecrets packs the three secrets into one sealed blob. They are
// always needed together, so sealing them separately would be three
// ciphertexts guarding one decision.
func encodeLoginSecrets(secrets loginSecrets) string {
	return strings.Join([]string{secrets.state, secrets.nonce, secrets.verifier}, "\n")
}

func decodeLoginSecrets(plaintext string) (loginSecrets, error) {
	parts := strings.Split(plaintext, "\n")
	if len(parts) != 3 {
		return loginSecrets{}, errors.New("the sealed login secrets are malformed")
	}
	return loginSecrets{state: parts[0], nonce: parts[1], verifier: parts[2]}, nil
}

// authorizationURL builds the redirect, including mandatory outbound PKCE.
func authorizationURL(
	stored federationProvider,
	secrets loginSecrets,
	redirectURI string,
) string {
	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", stored.Provider.ClientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("scope", strings.Join(stored.Provider.Scopes, " "))
	query.Set("state", secrets.state)
	query.Set("nonce", secrets.nonce)
	query.Set("code_challenge", federationdomain.Challenge(secrets.verifier))
	query.Set("code_challenge_method", "S256")
	return stored.Metadata.AuthorizationEndpoint + "?" + query.Encode()
}

// LoginExchange returns the token request the host must perform.
//
// The state is checked here, before the engine hands out anything: a callback
// that does not match the request SESAME started is not one to act on.
func (s *Service) LoginExchange(
	ctx context.Context,
	tenantID, loginID, state, code string,
) (FetchInstruction, error) {
	if err := federationdomain.ValidateLoginID(loginID); err != nil {
		return FetchInstruction{}, err
	}
	if code == "" {
		return FetchInstruction{}, ErrAssertionRejected
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	login, stored, secrets, err := s.pendingLoginLocked(tenantID, loginID)
	if err != nil {
		return FetchInstruction{}, err
	}
	if !federationdomain.MatchState(state, login.StateDigest) {
		return FetchInstruction{}, ErrAssertionRejected
	}
	return s.tokenInstruction(stored, login, secrets, code)
}

// pendingLoginLocked resolves a usable login and opens its secrets.
func (s *Service) pendingLoginLocked(
	tenantID, loginID string,
) (federationdomain.Login, federationProvider, loginSecrets, error) {
	login, err := s.lookupLoginLocked(tenantID, loginID)
	if err != nil {
		return federationdomain.Login{}, federationProvider{}, loginSecrets{}, err
	}
	stored, err := s.configuredProviderLocked(tenantID, login.ProviderID)
	if err != nil {
		return federationdomain.Login{}, federationProvider{}, loginSecrets{}, err
	}
	secrets, err := s.openLoginSecretsLocked(loginID)
	if err != nil {
		return federationdomain.Login{}, federationProvider{}, loginSecrets{}, err
	}
	return login, stored, secrets, nil
}

func (s *Service) openLoginSecretsLocked(loginID string) (loginSecrets, error) {
	sealed, exists := s.federatedSecrets[loginID]
	if !exists {
		return loginSecrets{}, ErrFederatedLoginNotFound
	}
	plaintext, err := authenticatordomain.Open(s.secretsKey, sealed)
	if err != nil {
		return loginSecrets{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	return decodeLoginSecrets(plaintext)
}

// tokenInstruction builds the exchange the host performs. The client secret
// leaves the engine here because the host makes the call; that is inherent to
// the egress boundary and is documented in docs/FEDERATION.md.
func (s *Service) tokenInstruction(
	stored federationProvider,
	login federationdomain.Login,
	secrets loginSecrets,
	code string,
) (FetchInstruction, error) {
	form := map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  login.RedirectURI,
		"client_id":     stored.Provider.ClientID,
		"code_verifier": secrets.verifier,
	}
	secret, err := s.openProviderSecret(stored.SecretSealed)
	if err != nil {
		return FetchInstruction{}, err
	}
	if secret != "" {
		form["client_secret"] = secret
	}
	return FetchInstruction{
		URL:    stored.Metadata.TokenEndpoint,
		Method: "POST",
		Form:   form,
	}, nil
}

func (s *Service) openProviderSecret(sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	secret, err := authenticatordomain.Open(s.secretsKey, sealed)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	return secret, nil
}

// FederatedSession is the outcome of a completed federated login.
type FederatedSession struct {
	Session     IssuedSession `json:"session"`
	PrincipalID string        `json:"principal_id"`
	Provisioned bool          `json:"provisioned,omitempty"`
}

// LoginComplete verifies a provider's ID token and issues a SESAME session.
//
// Everything the provider said is checked before anything is created: the
// signature first, then every claim, then the link. A failure records why in
// the audit ledger and returns one opaque reason.
func (s *Service) LoginComplete(
	ctx context.Context,
	tenantID, loginID, idToken, actor string,
) (FederatedSession, error) {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return FederatedSession{}, err
	}
	if err := federationdomain.ValidateLoginID(loginID); err != nil {
		return FederatedSession{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	login, stored, secrets, err := s.pendingLoginLocked(tenantID, loginID)
	if err != nil {
		return FederatedSession{}, err
	}
	assertion, err := s.verifyAssertionLocked(ctx, login, stored, secrets, idToken, actor)
	if err != nil {
		return FederatedSession{}, err
	}
	return s.completeLoginLocked(ctx, login, stored, assertion, actor)
}

// verifyAssertionLocked checks the token and audits a rejection.
func (s *Service) verifyAssertionLocked(
	ctx context.Context,
	login federationdomain.Login,
	stored federationProvider,
	secrets loginSecrets,
	idToken, actor string,
) (federationdomain.Assertion, error) {
	assertion, err := federationdomain.VerifyIDToken(
		idToken, stored.Keys,
		stored.Provider.Issuer, stored.Provider.ClientID,
		secrets.nonce, s.now())
	if err == nil {
		return assertion, nil
	}
	s.failLoginLocked(ctx, login, rejectionReason(err), actor)
	return federationdomain.Assertion{}, ErrAssertionRejected
}

// rejectionReason maps a verification failure to a stable audit code. The
// caller never sees it; an operator diagnosing a broken provider does.
func rejectionReason(err error) string {
	switch {
	case errors.Is(err, federationdomain.ErrUnknownKey):
		return "unknown_key"
	case errors.Is(err, federationdomain.ErrAssertionExpired):
		return "expired"
	case errors.Is(err, federationdomain.ErrNonceMismatch):
		return "nonce_mismatch"
	default:
		return "invalid_assertion"
	}
}

func (s *Service) failLoginLocked(
	ctx context.Context,
	login federationdomain.Login,
	reason, actor string,
) {
	event, err := s.ledger.Append(ctx, federationdomain.EventLoginFailed, login.TenantID, actor,
		federationdomain.LoginFailedPayload{
			LoginID:    login.ID,
			TenantID:   login.TenantID,
			ProviderID: login.ProviderID,
			Reason:     reason,
			FailedAt:   s.now().Format(time.RFC3339Nano),
		})
	if err != nil {
		s.logger.ErrorContext(ctx, "recording a federated login failure failed",
			"login_id", login.ID, "error", err)
		return
	}
	if err := s.applyLoginFailed(event); err != nil {
		s.logger.ErrorContext(ctx, "applying a federated login failure failed",
			"login_id", login.ID, "error", err)
	}
}

// completeLoginLocked resolves the principal and issues the session.
func (s *Service) completeLoginLocked(
	ctx context.Context,
	login federationdomain.Login,
	stored federationProvider,
	assertion federationdomain.Assertion,
	actor string,
) (FederatedSession, error) {
	subject := subjectFromAssertion(stored.Provider, assertion)
	if subject == "" {
		s.failLoginLocked(ctx, login, "missing_subject", actor)
		return FederatedSession{}, ErrAssertionRejected
	}
	hash := federationdomain.SubjectHash(stored.Provider.ID, subject)
	principalID, provisioned, err := s.resolvePrincipalLocked(ctx, stored, assertion, hash, actor)
	if err != nil {
		return FederatedSession{}, err
	}
	session, err := s.issueFederatedSessionLocked(ctx, login, principalID, actor)
	if err != nil {
		return FederatedSession{}, err
	}
	if err := s.appendLoginCompleted(ctx, login, principalID, hash, provisioned, actor); err != nil {
		return FederatedSession{}, err
	}
	s.writeSnapshotLocked(ctx, login.ID)
	return FederatedSession{Session: session, PrincipalID: principalID, Provisioned: provisioned}, nil
}

// subjectFromAssertion reads the configured subject claim, defaulting to the
// verified `sub` when the configured claim is absent.
func subjectFromAssertion(
	provider federationdomain.Provider,
	assertion federationdomain.Assertion,
) string {
	if provider.SubjectClaim == "" || provider.SubjectClaim == "sub" {
		return assertion.Subject
	}
	if value, ok := assertion.Claims[provider.SubjectClaim].(string); ok {
		return value
	}
	return ""
}

// resolvePrincipalLocked finds or creates the principal this subject means.
func (s *Service) resolvePrincipalLocked(
	ctx context.Context,
	stored federationProvider,
	assertion federationdomain.Assertion,
	hash, actor string,
) (string, bool, error) {
	if principalID, linked := s.federatedLinks[hash]; linked {
		return principalID, false, s.checkPrincipalActiveLocked(principalID)
	}
	if stored.Provider.Linking == federationdomain.LinkingStrict {
		return "", false, ErrSubjectNotLinked
	}
	return s.linkByVerifiedEmailLocked(ctx, stored, assertion, hash, actor)
}

func (s *Service) checkPrincipalActiveLocked(principalID string) error {
	if s.principals[principalID].Status != principaldomain.StatusActive {
		return ErrSubjectNotLinked
	}
	return nil
}

// issueFederatedSessionLocked mints the session. Assurance is the provider's
// single factor: SESAME did not see a second one, and claiming otherwise
// would let federation bypass a step-up requirement.
func (s *Service) issueFederatedSessionLocked(
	ctx context.Context,
	login federationdomain.Login,
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

func (s *Service) appendLoginCompleted(
	ctx context.Context,
	login federationdomain.Login,
	principalID, hash string,
	provisioned bool,
	actor string,
) error {
	event, err := s.ledger.Append(ctx, federationdomain.EventLoginCompleted, login.TenantID, actor,
		federationdomain.LoginCompletedPayload{
			LoginID:     login.ID,
			TenantID:    login.TenantID,
			ProviderID:  login.ProviderID,
			PrincipalID: principalID,
			SubjectHash: hash,
			Provisioned: provisioned,
			CompletedAt: s.now().Format(time.RFC3339Nano),
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	return s.applyLoginCompleted(event)
}

// linkByVerifiedEmailLocked matches or provisions a principal from a verified
// email claim.
//
// The verification flag is mandatory. An unverified email is a string the
// user typed at the provider, and treating it as an identity claim would let
// anyone who can register at that provider take over an existing SESAME
// account by claiming its address.
func (s *Service) linkByVerifiedEmailLocked(
	ctx context.Context,
	stored federationProvider,
	assertion federationdomain.Assertion,
	hash, actor string,
) (string, bool, error) {
	email, err := verifiedEmail(stored.Provider, assertion)
	if err != nil {
		return "", false, err
	}
	key := identifierKey(stored.Provider.TenantID, identifierNamespaceEmail, email)
	if principalID, claimed := s.identifiers[key]; claimed {
		if err := s.checkPrincipalActiveLocked(principalID); err != nil {
			return "", false, err
		}
		return principalID, false, s.appendSubjectLinked(ctx, stored, principalID, hash, actor)
	}
	principalID, err := s.provisionPrincipalLocked(ctx, stored, email, actor)
	if err != nil {
		return "", false, err
	}
	return principalID, true, nil
}

// identifierNamespaceEmail is the namespace a federated email claim is
// matched and provisioned under.
const identifierNamespaceEmail = "email"

// verifiedEmail reads the configured email claim and refuses it unless the
// provider says it verified it.
func verifiedEmail(
	provider federationdomain.Provider,
	assertion federationdomain.Assertion,
) (string, error) {
	email, ok := assertion.Claims[provider.EmailClaim].(string)
	if !ok || email == "" {
		return "", ErrSubjectNotLinked
	}
	if verified, ok := assertion.Claims["email_verified"].(bool); !ok || !verified {
		return "", ErrSubjectNotLinked
	}
	return principaldomain.NormalizeIdentifier(email), nil
}

// provisionPrincipalLocked creates a principal for a first-time federated
// user, then links the external subject to it.
func (s *Service) provisionPrincipalLocked(
	ctx context.Context,
	stored federationProvider,
	email, actor string,
) (string, error) {
	identifier := principaldomain.Identifier{
		Namespace: identifierNamespaceEmail,
		Value:     email,
	}
	if err := principaldomain.ValidateIdentifier(identifier); err != nil {
		return "", err
	}
	principalID, err := principaldomain.NewID()
	if err != nil {
		return "", err
	}
	if err := s.appendPrincipalCreated(ctx, stored, principalID, identifier, actor); err != nil {
		return "", err
	}
	return principalID, nil
}

func (s *Service) appendPrincipalCreated(
	ctx context.Context,
	stored federationProvider,
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

// appendSubjectLinked records an external subject binding to an existing
// principal.
func (s *Service) appendSubjectLinked(
	ctx context.Context,
	stored federationProvider,
	principalID, hash, actor string,
) error {
	event, err := s.ledger.Append(ctx, federationdomain.EventSubjectLinked,
		stored.Provider.TenantID, actor,
		federationdomain.SubjectLinkedPayload{
			TenantID:    stored.Provider.TenantID,
			ProviderID:  stored.Provider.ID,
			PrincipalID: principalID,
			SubjectHash: hash,
			LinkedAt:    s.now().Format(time.RFC3339Nano),
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	return s.applySubjectLinked(event)
}

// newProviderIdentity mints the provider's identifier and seals its secret.
func (s *Service) newProviderIdentity(clientSecret string) (string, string, error) {
	providerID, err := federationdomain.NewProviderID()
	if err != nil {
		return "", "", err
	}
	sealed, err := s.sealProviderSecret(clientSecret)
	if err != nil {
		return "", "", err
	}
	return providerID, sealed, nil
}

// lookupLoginLocked resolves a login within its tenant and checks it is still
// usable. An unknown login and another tenant's login return one error:
// telling them apart would confirm that a login exists.
func (s *Service) lookupLoginLocked(
	tenantID, loginID string,
) (federationdomain.Login, error) {
	login, exists := s.federatedLogins[loginID]
	if !exists || login.TenantID != tenantID {
		return federationdomain.Login{}, ErrFederatedLoginNotFound
	}
	if err := login.Usable(s.now()); err != nil {
		return federationdomain.Login{}, err
	}
	return login, nil
}

// ProviderView is a provider as an operator sees it, plus whether SESAME has
// validated metadata for it. The sealed client secret is never included.
type ProviderView struct {
	Provider   federationdomain.Provider `json:"provider"`
	Configured bool                      `json:"configured"`
	// Issuer endpoints are reported so an operator can confirm what SESAME
	// resolved, rather than having to infer it from a failed login.
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string `json:"token_endpoint,omitempty"`
	JWKSURI               string `json:"jwks_uri,omitempty"`
	KeyCount              int    `json:"key_count,omitempty"`
}

// ProviderGet reports one provider within its tenant.
func (s *Service) ProviderGet(tenantID, providerID string) (ProviderView, error) {
	if err := federationdomain.ValidateProviderID(providerID); err != nil {
		return ProviderView{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, err := s.usableProviderLocked(tenantID, providerID)
	if err != nil {
		return ProviderView{}, err
	}
	return ProviderView{
		Provider:              stored.Provider,
		Configured:            stored.Configured,
		AuthorizationEndpoint: stored.Metadata.AuthorizationEndpoint,
		TokenEndpoint:         stored.Metadata.TokenEndpoint,
		JWKSURI:               stored.Metadata.JWKSURI,
		KeyCount:              len(stored.Keys.Keys),
	}, nil
}

// ProviderDisable durably stops new federated logins through one provider.
//
// Existing links and sessions survive: disabling a provider says "stop
// trusting new assertions from here", not "forget who these people are". An
// operator who wants the sessions gone revokes them separately, and one whose
// provider is compromised wants both — in that order, because a provider that
// can still mint assertions makes session revocation pointless.
//
// Disabling twice is idempotent and appends no second event.
func (s *Service) ProviderDisable(
	ctx context.Context,
	tenantID, providerID, reason, actor string,
) error {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return err
	}
	if err := federationdomain.ValidateProviderID(providerID); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, exists := s.providers[providerID]
	if !exists || stored.Provider.TenantID != tenantID {
		return ErrProviderNotFound
	}
	if stored.Provider.Disabled {
		return nil
	}
	return s.appendProviderDisabled(ctx, tenantID, providerID, reason, actor)
}

func (s *Service) appendProviderDisabled(
	ctx context.Context,
	tenantID, providerID, reason, actor string,
) error {
	event, err := s.ledger.Append(ctx, federationdomain.EventProviderDisabled, tenantID, actor,
		federationdomain.ProviderDisabledPayload{
			ProviderID: providerID,
			TenantID:   tenantID,
			Reason:     reason,
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyProviderDisabled(event); err != nil {
		return err
	}
	s.writeSnapshotLocked(ctx, providerID)
	return nil
}
