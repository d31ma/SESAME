package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/d31ma/sesame/internal/domain/audit"
	authndomain "github.com/d31ma/sesame/internal/domain/authentication"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	sessiondomain "github.com/d31ma/sesame/internal/domain/session"
	tenantdomain "github.com/d31ma/sesame/internal/domain/tenant"
)

// Stable authentication errors.
var (
	ErrTransactionNotFound = errors.New("authentication transaction not found")
	ErrTransactionClosed   = errors.New("authentication transaction accepts no further attempts")
	ErrSessionNotFound     = errors.New("session not found")
	ErrSessionInactive     = errors.New("session is expired or revoked")
	ErrNoCredential        = errors.New("principal has no usable credential")
)

// AuthenticationResult reports the state of a transaction after a command.
// It never carries a reason that distinguishes a known identifier from an
// unknown one.
type AuthenticationResult struct {
	TransactionID string `json:"transaction_id"`
	State         string `json:"state"`
	Assurance     string `json:"assurance,omitempty"`
	FailureCode   string `json:"failure_code,omitempty"`
	AttemptsLeft  int    `json:"attempts_left"`
}

// IssuedSession is returned once, at completion. The secret is never
// recoverable afterwards: only its digest is durable.
type IssuedSession struct {
	SessionID   string `json:"session_id"`
	Secret      string `json:"session_secret"`
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id"`
	ExpiresAt   string `json:"expires_at"`
	Assurance   string `json:"assurance"`
}

// PasswordSet stores an Argon2id verifier for a principal, replacing any
// existing one. The plaintext never leaves this call.
func (s *Service) PasswordSet(ctx context.Context, principalID, password, actor string) error {
	if err := s.requireLedger(); err != nil {
		return err
	}
	if err := principaldomain.ValidateID(principalID); err != nil {
		return err
	}
	if err := authenticatordomain.ValidatePassword(password); err != nil {
		return err
	}
	if actor == "" {
		return errors.New("actor is required")
	}
	verifier, err := authenticatordomain.NewPasswordVerifier(password)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	principal, exists := s.principals[principalID]
	if !exists {
		return ErrPrincipalNotFound
	}
	event, err := s.ledger.Append(ctx, authenticatordomain.EventPasswordSet, principal.TenantID, actor,
		authenticatordomain.PasswordSetPayload{
			PrincipalID: principalID,
			TenantID:    principal.TenantID,
			Verifier:    verifier,
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyPasswordSet(event); err != nil {
		return err
	}
	s.writeSnapshotLocked(ctx, principalID)
	return nil
}

// AuthenticationBegin starts a transaction for one identifier.
//
// It succeeds whether or not the identifier resolves. A caller cannot learn
// which identifiers exist by watching this call, and a suspended principal
// is treated exactly like an unknown one: the transaction runs and fails at
// the same point with the same reason.
func (s *Service) AuthenticationBegin(
	ctx context.Context,
	tenantID string,
	identifier principaldomain.Identifier,
	actor string,
) (AuthenticationResult, error) {
	if err := s.requireLedger(); err != nil {
		return AuthenticationResult{}, err
	}
	if err := tenantdomain.ValidateID(tenantID); err != nil {
		return AuthenticationResult{}, err
	}
	identifier.Value = principaldomain.NormalizeIdentifier(identifier.Value)
	if err := principaldomain.ValidateIdentifier(identifier); err != nil {
		return AuthenticationResult{}, err
	}
	if actor == "" {
		return AuthenticationResult{}, errors.New("actor is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[tenantID]; !exists {
		return AuthenticationResult{}, ErrNotFound
	}

	// Resolve without leaking the outcome: a suspended or absent principal
	// leaves PrincipalID empty and the transaction proceeds regardless.
	principalID := ""
	if candidate, exists := s.identifiers[identifierKey(tenantID, identifier.Namespace, identifier.Value)]; exists {
		if s.principals[candidate].Status == principaldomain.StatusActive {
			principalID = candidate
		}
	}

	id, err := authndomain.NewID()
	if err != nil {
		return AuthenticationResult{}, err
	}
	// Every transaction carries a passkey challenge whether or not the
	// principal has one registered. Issuing it only for principals that do
	// would tell an attacker which accounts have passkeys.
	passkeyChallenge, err := authenticatordomain.NewPasskeyChallenge()
	if err != nil {
		return AuthenticationResult{}, err
	}
	now := s.now()
	event, err := s.ledger.Append(ctx, authndomain.EventStarted, tenantID, actor, authndomain.StartedPayload{
		TransactionID:       id,
		TenantID:            tenantID,
		PrincipalID:         principalID,
		IdentifierNamespace: identifier.Namespace,
		StartedAt:           now.Format(time.RFC3339Nano),
		ExpiresAt:           now.Add(authndomain.Lifetime).Format(time.RFC3339Nano),
		PasskeyChallenge:    passkeyChallenge,
	})
	if err != nil {
		return AuthenticationResult{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyAuthenticationStarted(event); err != nil {
		return AuthenticationResult{}, err
	}
	return s.authenticationResultLocked(id), nil
}

// AuthenticationVerifyPassword supplies a password to a running transaction.
//
// Every rejection path costs the same Argon2id work: an unresolved
// transaction verifies the password against a decoy verifier so that timing
// does not reveal whether the identifier existed.
func (s *Service) AuthenticationVerifyPassword(
	ctx context.Context,
	transactionID string,
	password string,
	actor string,
) (AuthenticationResult, error) {
	if err := s.requireLedger(); err != nil {
		return AuthenticationResult{}, err
	}
	if err := authndomain.ValidateID(transactionID); err != nil {
		return AuthenticationResult{}, err
	}
	if actor == "" {
		return AuthenticationResult{}, errors.New("actor is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	transaction, exists := s.transactions[transactionID]
	if !exists {
		return AuthenticationResult{}, ErrTransactionNotFound
	}
	if allowed, reason := transaction.CanAttempt(s.now()); !allowed {
		if !authndomain.Terminal(transaction.State) {
			if err := s.failTransactionLocked(ctx, transaction, reason, actor); err != nil {
				return AuthenticationResult{}, err
			}
		}
		return s.authenticationResultLocked(transactionID), ErrTransactionClosed
	}

	verifier := s.passwords[transaction.PrincipalID]
	if verifier == "" {
		verifier = s.decoyVerifier
	}
	matched, needsUpgrade, err := authenticatordomain.VerifyPassword(verifier, password)
	if err != nil {
		// A stored verifier this binary cannot read is an operational
		// failure, not a wrong password.
		return AuthenticationResult{}, fmt.Errorf("%w: %v", ErrNoCredential, err)
	}
	// A transaction that never resolved a principal can never succeed, no
	// matter what the decoy comparison returned.
	if transaction.PrincipalID == "" {
		matched = false
	}

	if !matched {
		attempts := transaction.Attempts + 1
		reason := authndomain.ReasonInvalidCredentials
		if attempts >= authndomain.MaxAttempts {
			reason = authndomain.ReasonAttemptsExhausted
		}
		event, err := s.ledger.Append(ctx, authndomain.EventFailed, transaction.TenantID, actor,
			authndomain.FailedPayload{
				TransactionID: transactionID,
				TenantID:      transaction.TenantID,
				Reason:        reason,
				Attempts:      attempts,
			})
		if err != nil {
			return AuthenticationResult{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
		}
		if err := s.applyAuthenticationFailed(event); err != nil {
			return AuthenticationResult{}, err
		}
		s.writeSnapshotLocked(ctx, transactionID)
		return s.authenticationResultLocked(transactionID), nil
	}

	event, err := s.ledger.Append(ctx, authndomain.EventFactorVerified, transaction.TenantID, actor,
		authndomain.FactorVerifiedPayload{
			TransactionID: transactionID,
			TenantID:      transaction.TenantID,
			PrincipalID:   transaction.PrincipalID,
			Factor:        authndomain.FactorPassword,
			Assurance:     authndomain.AssurancePassword,
			Attempts:      transaction.Attempts + 1,
		})
	if err != nil {
		return AuthenticationResult{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyAuthenticationFactorVerified(event); err != nil {
		return AuthenticationResult{}, err
	}

	// Transparently raise the stored cost when the verifier predates the
	// current parameters. A failure here must not fail the login: the
	// credential is already proven correct.
	if needsUpgrade {
		if upgraded, upgradeErr := authenticatordomain.NewPasswordVerifier(password); upgradeErr == nil {
			if _, appendErr := s.ledger.Append(ctx, authenticatordomain.EventPasswordSet,
				transaction.TenantID, "system:parameter-upgrade",
				authenticatordomain.PasswordSetPayload{
					PrincipalID: transaction.PrincipalID,
					TenantID:    transaction.TenantID,
					Verifier:    upgraded,
				}); appendErr == nil {
				s.passwords[transaction.PrincipalID] = upgraded
				s.logger.Info("password verifier upgraded to current cost",
					"principal_id", transaction.PrincipalID)
			} else {
				s.logger.Warn("password verifier upgrade could not be stored",
					"principal_id", transaction.PrincipalID, "error", appendErr.Error())
			}
		}
	}
	s.writeSnapshotLocked(ctx, transactionID)
	return s.authenticationResultLocked(transactionID), nil
}

// AuthenticationComplete issues a session for a transaction whose factors
// are satisfied. The returned secret is the only copy.
func (s *Service) AuthenticationComplete(
	ctx context.Context,
	transactionID string,
	lifetime time.Duration,
	actor string,
) (IssuedSession, error) {
	if err := s.requireLedger(); err != nil {
		return IssuedSession{}, err
	}
	if err := authndomain.ValidateID(transactionID); err != nil {
		return IssuedSession{}, err
	}
	if actor == "" {
		return IssuedSession{}, errors.New("actor is required")
	}
	bounded, err := sessiondomain.Lifetime(lifetime)
	if err != nil {
		return IssuedSession{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	transaction, exists := s.transactions[transactionID]
	if !exists {
		return IssuedSession{}, ErrTransactionNotFound
	}
	now := s.now()
	if transaction.Expired(now) && !authndomain.Terminal(transaction.State) {
		if err := s.failTransactionLocked(ctx, transaction, authndomain.ReasonExpired, actor); err != nil {
			return IssuedSession{}, err
		}
		return IssuedSession{}, ErrTransactionClosed
	}
	if err := authndomain.ValidateTransition(transaction.State, authndomain.StateCompleted); err != nil {
		return IssuedSession{}, fmt.Errorf("%w: %v", ErrTransactionClosed, err)
	}
	if transaction.PrincipalID == "" || transaction.Assurance == "" {
		return IssuedSession{}, ErrTransactionClosed
	}
	// A principal suspended between factor verification and completion must
	// not receive a session.
	if s.principals[transaction.PrincipalID].Status != principaldomain.StatusActive {
		if err := s.failTransactionLocked(ctx, transaction, authndomain.ReasonInvalidCredentials, actor); err != nil {
			return IssuedSession{}, err
		}
		return IssuedSession{}, ErrTransactionClosed
	}

	sessionID, err := sessiondomain.NewID()
	if err != nil {
		return IssuedSession{}, err
	}
	secret, digest, err := sessiondomain.NewSecret()
	if err != nil {
		return IssuedSession{}, err
	}
	expiresAt := now.Add(bounded).Format(time.RFC3339Nano)

	issued, err := s.ledger.Append(ctx, sessiondomain.EventIssued, transaction.TenantID, actor,
		sessiondomain.IssuedPayload{
			SessionID:    sessionID,
			TenantID:     transaction.TenantID,
			PrincipalID:  transaction.PrincipalID,
			IssuedAt:     now.Format(time.RFC3339Nano),
			ExpiresAt:    expiresAt,
			SecretDigest: digest,
			Assurance:    transaction.Assurance,
		})
	if err != nil {
		return IssuedSession{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applySessionIssued(issued); err != nil {
		return IssuedSession{}, err
	}
	completed, err := s.ledger.Append(ctx, authndomain.EventCompleted, transaction.TenantID, actor,
		authndomain.CompletedPayload{
			TransactionID: transactionID,
			TenantID:      transaction.TenantID,
			PrincipalID:   transaction.PrincipalID,
			SessionID:     sessionID,
		})
	if err != nil {
		return IssuedSession{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyAuthenticationCompleted(completed); err != nil {
		return IssuedSession{}, err
	}
	s.writeSnapshotLocked(ctx, sessionID)

	return IssuedSession{
		SessionID:   sessionID,
		Secret:      secret,
		TenantID:    transaction.TenantID,
		PrincipalID: transaction.PrincipalID,
		ExpiresAt:   expiresAt,
		Assurance:   transaction.Assurance,
	}, nil
}

// SessionVerify checks a presented session secret and returns the session
// when it is active. Expiry, revocation, and a suspended principal all deny.
func (s *Service) SessionVerify(sessionID, secret string) (sessiondomain.Session, error) {
	if err := sessiondomain.ValidateID(sessionID); err != nil {
		return sessiondomain.Session{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifySessionLocked(sessionID, secret, s.now())
}

// verifySessionLocked is the single rule for "is this session usable right
// now", shared by session.verify, step-up decisions, and the OIDC flow, so no
// caller can end up with a laxer version of it.
//
// A wrong secret and an unknown session return one error on purpose: telling
// them apart would confirm that a session ID exists.
func (s *Service) verifySessionLocked(
	sessionID string,
	secret string,
	now time.Time,
) (sessiondomain.Session, error) {
	stored, exists := s.sessions[sessionID]
	if !exists || !sessiondomain.VerifySecret(stored.SecretDigest, secret) {
		return sessiondomain.Session{}, ErrSessionNotFound
	}
	if !stored.Active(now) {
		return sessiondomain.Session{}, ErrSessionInactive
	}
	if s.principals[stored.PrincipalID].Status != principaldomain.StatusActive {
		return sessiondomain.Session{}, ErrSessionInactive
	}
	return stored, nil
}

// SessionRevoke durably ends a session. Revoking an already revoked session
// is idempotent so an emergency response can be retried.
func (s *Service) SessionRevoke(ctx context.Context, sessionID, reason, actor string) error {
	if err := s.requireLedger(); err != nil {
		return err
	}
	if err := sessiondomain.ValidateID(sessionID); err != nil {
		return err
	}
	if actor == "" {
		return errors.New("actor is required")
	}
	if reason == "" {
		reason = "operator_revoked"
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, exists := s.sessions[sessionID]
	if !exists {
		return ErrSessionNotFound
	}
	if stored.Status == sessiondomain.StatusRevoked {
		return nil
	}
	event, err := s.ledger.Append(ctx, sessiondomain.EventRevoked, stored.TenantID, actor,
		sessiondomain.RevokedPayload{
			SessionID: sessionID,
			TenantID:  stored.TenantID,
			Reason:    reason,
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applySessionRevoked(event); err != nil {
		return err
	}
	s.writeSnapshotLocked(ctx, sessionID)
	return nil
}

func (s *Service) failTransactionLocked(
	ctx context.Context,
	transaction authndomain.Transaction,
	reason string,
	actor string,
) error {
	event, err := s.ledger.Append(ctx, authndomain.EventFailed, transaction.TenantID, actor,
		authndomain.FailedPayload{
			TransactionID: transaction.ID,
			TenantID:      transaction.TenantID,
			Reason:        reason,
			Attempts:      transaction.Attempts,
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	return s.applyAuthenticationFailed(event)
}

func (s *Service) authenticationResultLocked(transactionID string) AuthenticationResult {
	transaction := s.transactions[transactionID]
	remaining := authndomain.MaxAttempts - transaction.Attempts
	if remaining < 0 || authndomain.Terminal(transaction.State) {
		remaining = 0
	}
	return AuthenticationResult{
		TransactionID: transaction.ID,
		State:         transaction.State,
		Assurance:     transaction.Assurance,
		FailureCode:   transaction.FailureCode,
		AttemptsLeft:  remaining,
	}
}

func (s *Service) applyPasswordSet(event audit.Event) error {
	var payload authenticatordomain.PasswordSetPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	if _, exists := s.principals[payload.PrincipalID]; !exists {
		return fmt.Errorf("event sequence %d sets a password for an unknown principal", event.Sequence)
	}
	s.passwords[payload.PrincipalID] = payload.Verifier
	return nil
}

func (s *Service) applyAuthenticationStarted(event audit.Event) error {
	var payload authndomain.StartedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	if err := authndomain.ValidateID(payload.TransactionID); err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	if _, exists := s.transactions[payload.TransactionID]; exists {
		return fmt.Errorf("event sequence %d starts a duplicate transaction", event.Sequence)
	}
	s.transactions[payload.TransactionID] = authndomain.Transaction{
		ID:               payload.TransactionID,
		TenantID:         payload.TenantID,
		PrincipalID:      payload.PrincipalID,
		State:            authndomain.StateAwaitingFactor,
		StartedAt:        payload.StartedAt,
		ExpiresAt:        payload.ExpiresAt,
		PasskeyChallenge: payload.PasskeyChallenge,
	}
	return nil
}

func (s *Service) applyAuthenticationFactorVerified(event audit.Event) error {
	var payload authndomain.FactorVerifiedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	transaction, exists := s.transactions[payload.TransactionID]
	if !exists {
		return fmt.Errorf("event sequence %d verifies an unknown transaction", event.Sequence)
	}
	if err := authndomain.ValidateTransition(transaction.State, authndomain.StateAwaitingFactor); err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	transaction.Attempts = payload.Attempts
	transaction.Assurance = payload.Assurance
	s.transactions[payload.TransactionID] = transaction
	return nil
}

func (s *Service) applyAuthenticationFailed(event audit.Event) error {
	var payload authndomain.FailedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	transaction, exists := s.transactions[payload.TransactionID]
	if !exists {
		return fmt.Errorf("event sequence %d fails an unknown transaction", event.Sequence)
	}
	transaction.Attempts = payload.Attempts
	// A recoverable failure keeps the transaction open; a terminal one
	// closes it. Both are checked against the declared machine.
	target := authndomain.StateAwaitingFactor
	if payload.Reason != authndomain.ReasonInvalidCredentials ||
		payload.Attempts >= authndomain.MaxAttempts {
		target = authndomain.StateFailed
		transaction.FailureCode = payload.Reason
	}
	if err := authndomain.ValidateTransition(transaction.State, target); err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	transaction.State = target
	s.transactions[payload.TransactionID] = transaction
	return nil
}

func (s *Service) applyAuthenticationCompleted(event audit.Event) error {
	var payload authndomain.CompletedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	transaction, exists := s.transactions[payload.TransactionID]
	if !exists {
		return fmt.Errorf("event sequence %d completes an unknown transaction", event.Sequence)
	}
	if err := authndomain.ValidateTransition(transaction.State, authndomain.StateCompleted); err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	transaction.State = authndomain.StateCompleted
	transaction.SessionID = payload.SessionID
	s.transactions[payload.TransactionID] = transaction
	return nil
}

func (s *Service) applySessionIssued(event audit.Event) error {
	var payload sessiondomain.IssuedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	if err := sessiondomain.ValidateID(payload.SessionID); err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	if _, exists := s.sessions[payload.SessionID]; exists {
		return fmt.Errorf("event sequence %d issues a duplicate session", event.Sequence)
	}
	if _, exists := s.principals[payload.PrincipalID]; !exists {
		return fmt.Errorf("event sequence %d issues a session for an unknown principal", event.Sequence)
	}
	s.sessions[payload.SessionID] = sessiondomain.Session{
		ID:           payload.SessionID,
		TenantID:     payload.TenantID,
		PrincipalID:  payload.PrincipalID,
		Status:       sessiondomain.StatusActive,
		IssuedAt:     payload.IssuedAt,
		ExpiresAt:    payload.ExpiresAt,
		SecretDigest: payload.SecretDigest,
		Assurance:    payload.Assurance,
	}
	return nil
}

func (s *Service) applySessionRevoked(event audit.Event) error {
	var payload sessiondomain.RevokedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	stored, exists := s.sessions[payload.SessionID]
	if !exists || stored.TenantID != payload.TenantID {
		return fmt.Errorf("event sequence %d revokes an unknown session", event.Sequence)
	}
	stored.Status = sessiondomain.StatusRevoked
	s.sessions[payload.SessionID] = stored
	return nil
}
