package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/d31ma/sesame/internal/domain/audit"
	authndomain "github.com/d31ma/sesame/internal/domain/authentication"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
)

// Stable TOTP errors.
var (
	ErrTOTPNotEnrolled   = errors.New("principal has no TOTP authenticator")
	ErrTOTPNotActive     = errors.New("TOTP authenticator is enrolled but not activated")
	ErrTOTPAlreadyActive = errors.New("principal already has an active TOTP authenticator")
	ErrTOTPInvalidCode   = errors.New("TOTP code is not valid")
)

// totpAuthenticator is the stored state of one principal's TOTP factor.
type totpAuthenticator struct {
	SealedSecret string `json:"sealed_secret"`
	Active       bool   `json:"active"`
	// LastCounter is the highest time-step already spent. It is what makes a
	// replayed code detectable within its own validity window.
	LastCounter int64 `json:"last_counter"`
}

// TOTPEnroll issues a shared secret for a principal. The secret and its
// provisioning URI are returned exactly once and are never recoverable
// afterwards; only the sealed form is durable.
//
// The authenticator is not usable until TOTPActivate proves a code, so a
// mis-scanned or half-finished enrollment cannot lock anyone out of a factor
// they cannot actually produce.
func (s *Service) TOTPEnroll(
	ctx context.Context,
	principalID string,
	issuer string,
	actor string,
) (authenticatordomain.TOTPEnrollment, error) {
	if err := s.requireLedger(); err != nil {
		return authenticatordomain.TOTPEnrollment{}, err
	}
	if err := principaldomain.ValidateID(principalID); err != nil {
		return authenticatordomain.TOTPEnrollment{}, err
	}
	if actor == "" {
		return authenticatordomain.TOTPEnrollment{}, errors.New("actor is required")
	}
	if issuer == "" {
		issuer = "SESAME"
	}
	if len(s.secretsKey) == 0 {
		return authenticatordomain.TOTPEnrollment{}, authenticatordomain.ErrNoSealingKey
	}

	secret, err := authenticatordomain.NewTOTPSecret()
	if err != nil {
		return authenticatordomain.TOTPEnrollment{}, err
	}
	sealed, err := authenticatordomain.Seal(s.secretsKey, secret)
	if err != nil {
		return authenticatordomain.TOTPEnrollment{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	principal, exists := s.principals[principalID]
	if !exists {
		return authenticatordomain.TOTPEnrollment{}, ErrPrincipalNotFound
	}
	// Re-enrolling over an active factor would silently disable the one the
	// principal is actually carrying, so it is refused.
	if existing, enrolled := s.totp[principalID]; enrolled && existing.Active {
		return authenticatordomain.TOTPEnrollment{}, ErrTOTPAlreadyActive
	}

	event, err := s.ledger.Append(ctx, authenticatordomain.EventTOTPEnrolled, principal.TenantID, actor,
		authenticatordomain.TOTPEnrolledPayload{
			PrincipalID:  principalID,
			TenantID:     principal.TenantID,
			SealedSecret: sealed,
		})
	if err != nil {
		return authenticatordomain.TOTPEnrollment{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyTOTPEnrolled(event); err != nil {
		return authenticatordomain.TOTPEnrollment{}, err
	}
	s.writeSnapshotLocked(ctx, principalID)

	return authenticatordomain.TOTPEnrollment{
		Secret: secret,
		ProvisioningURI: authenticatordomain.TOTPProvisioningURI(
			issuer, principal.Identifier.Value, secret),
	}, nil
}

// TOTPActivate proves an enrollment by verifying one code and makes the
// factor usable.
func (s *Service) TOTPActivate(
	ctx context.Context,
	principalID string,
	code string,
	actor string,
) error {
	if err := s.requireLedger(); err != nil {
		return err
	}
	if err := principaldomain.ValidateID(principalID); err != nil {
		return err
	}
	if actor == "" {
		return errors.New("actor is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	principal, exists := s.principals[principalID]
	if !exists {
		return ErrPrincipalNotFound
	}
	stored, enrolled := s.totp[principalID]
	if !enrolled {
		return ErrTOTPNotEnrolled
	}
	if stored.Active {
		return ErrTOTPAlreadyActive
	}

	matched, counter, err := s.verifyTOTPLocked(stored, code)
	if err != nil {
		return err
	}
	if !matched {
		return ErrTOTPInvalidCode
	}

	event, err := s.ledger.Append(ctx, authenticatordomain.EventTOTPActivated, principal.TenantID, actor,
		authenticatordomain.TOTPActivatedPayload{
			PrincipalID: principalID,
			TenantID:    principal.TenantID,
			Counter:     counter,
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyTOTPActivated(event); err != nil {
		return err
	}
	s.writeSnapshotLocked(ctx, principalID)
	return nil
}

// AuthenticationVerifyTOTP supplies a TOTP code to a running transaction that
// has already satisfied a first factor, raising its assurance to MFA.
//
// It refuses to run before a first factor: a one-time code alone proves
// possession of a device, not of the account.
func (s *Service) AuthenticationVerifyTOTP(
	ctx context.Context,
	transactionID string,
	code string,
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
	if transaction.Assurance == "" {
		return s.authenticationResultLocked(transactionID),
			fmt.Errorf("%w: a first factor must be verified before TOTP", ErrTransactionClosed)
	}

	stored, enrolled := s.totp[transaction.PrincipalID]
	matched := false
	counter := int64(0)
	if enrolled && stored.Active {
		var err error
		matched, counter, err = s.verifyTOTPLocked(stored, code)
		if err != nil {
			return AuthenticationResult{}, fmt.Errorf("%w: %v", ErrNoCredential, err)
		}
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

	// Spending the counter is a durable fact of its own: a replay must be
	// refused even after a restart that loses in-memory state.
	used, err := s.ledger.Append(ctx, authenticatordomain.EventTOTPUsed, transaction.TenantID, actor,
		authenticatordomain.TOTPUsedPayload{
			PrincipalID: transaction.PrincipalID,
			TenantID:    transaction.TenantID,
			Counter:     counter,
		})
	if err != nil {
		return AuthenticationResult{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyTOTPUsed(used); err != nil {
		return AuthenticationResult{}, err
	}

	event, err := s.ledger.Append(ctx, authndomain.EventFactorVerified, transaction.TenantID, actor,
		authndomain.FactorVerifiedPayload{
			TransactionID: transactionID,
			TenantID:      transaction.TenantID,
			PrincipalID:   transaction.PrincipalID,
			Factor:        authndomain.FactorTOTP,
			Assurance:     authndomain.AssuranceMFA,
			Attempts:      transaction.Attempts + 1,
		})
	if err != nil {
		return AuthenticationResult{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyAuthenticationFactorVerified(event); err != nil {
		return AuthenticationResult{}, err
	}
	s.writeSnapshotLocked(ctx, transactionID)
	return s.authenticationResultLocked(transactionID), nil
}

func (s *Service) verifyTOTPLocked(
	stored totpAuthenticator,
	code string,
) (bool, int64, error) {
	if len(s.secretsKey) == 0 {
		return false, 0, authenticatordomain.ErrNoSealingKey
	}
	secret, err := authenticatordomain.Open(s.secretsKey, stored.SealedSecret)
	if err != nil {
		return false, 0, err
	}
	return authenticatordomain.VerifyTOTPCode(secret, code, s.now(), stored.LastCounter)
}

func (s *Service) applyTOTPEnrolled(event audit.Event) error {
	var payload authenticatordomain.TOTPEnrolledPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	if _, exists := s.principals[payload.PrincipalID]; !exists {
		return fmt.Errorf("event sequence %d enrolls TOTP for an unknown principal", event.Sequence)
	}
	// Re-enrollment replaces the pending secret and resets the counter,
	// because the new secret has spent nothing.
	s.totp[payload.PrincipalID] = totpAuthenticator{SealedSecret: payload.SealedSecret}
	return nil
}

func (s *Service) applyTOTPActivated(event audit.Event) error {
	var payload authenticatordomain.TOTPActivatedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	stored, enrolled := s.totp[payload.PrincipalID]
	if !enrolled {
		return fmt.Errorf("event sequence %d activates an unenrolled authenticator", event.Sequence)
	}
	stored.Active = true
	if payload.Counter > stored.LastCounter {
		stored.LastCounter = payload.Counter
	}
	s.totp[payload.PrincipalID] = stored
	return nil
}

func (s *Service) applyTOTPUsed(event audit.Event) error {
	var payload authenticatordomain.TOTPUsedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	stored, enrolled := s.totp[payload.PrincipalID]
	if !enrolled {
		return fmt.Errorf("event sequence %d spends a counter for an unenrolled authenticator", event.Sequence)
	}
	// Counters only move forward, so replaying the ledger can never lower
	// the spent mark.
	if payload.Counter > stored.LastCounter {
		stored.LastCounter = payload.Counter
	}
	s.totp[payload.PrincipalID] = stored
	return nil
}
