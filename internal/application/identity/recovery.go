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

// ErrNoRecoveryCodes reports a principal with no unspent recovery codes.
var ErrNoRecoveryCodes = errors.New("principal has no unspent recovery codes")

// recoveryCodes is the stored state of one principal's backup factor: the
// digests still unspent.
type recoveryCodes struct {
	Unspent map[string]struct{}
}

// RecoveryCodesIssue generates a fresh set, replacing any existing one. The
// plaintext codes are returned exactly once and are never recoverable
// afterwards.
//
// Issuing invalidates every previous code, so a leaked set can be retired by
// issuing again.
func (s *Service) RecoveryCodesIssue(
	ctx context.Context,
	principalID string,
	actor string,
) (authenticatordomain.RecoveryCodeSet, error) {
	if err := s.requireLedger(); err != nil {
		return authenticatordomain.RecoveryCodeSet{}, err
	}
	if err := principaldomain.ValidateID(principalID); err != nil {
		return authenticatordomain.RecoveryCodeSet{}, err
	}
	if actor == "" {
		return authenticatordomain.RecoveryCodeSet{}, errors.New("actor is required")
	}

	codes, digests, err := authenticatordomain.NewRecoveryCodes()
	if err != nil {
		return authenticatordomain.RecoveryCodeSet{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	principal, exists := s.principals[principalID]
	if !exists {
		return authenticatordomain.RecoveryCodeSet{}, ErrPrincipalNotFound
	}
	event, err := s.ledger.Append(ctx, authenticatordomain.EventRecoveryCodesIssued,
		principal.TenantID, actor,
		authenticatordomain.RecoveryCodesIssuedPayload{
			PrincipalID: principalID,
			TenantID:    principal.TenantID,
			Digests:     digests,
		})
	if err != nil {
		return authenticatordomain.RecoveryCodeSet{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyRecoveryCodesIssued(event); err != nil {
		return authenticatordomain.RecoveryCodeSet{}, err
	}
	s.writeSnapshotLocked(ctx, principalID)
	return authenticatordomain.RecoveryCodeSet{Codes: codes}, nil
}

// RecoveryCodesRemaining reports how many codes a principal has left, so a
// host can prompt for reissue before the last one is gone.
func (s *Service) RecoveryCodesRemaining(principalID string) (int, error) {
	if err := principaldomain.ValidateID(principalID); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.principals[principalID]; !exists {
		return 0, ErrPrincipalNotFound
	}
	return len(s.recovery[principalID].Unspent), nil
}

// AuthenticationVerifyRecoveryCode spends one recovery code as a second
// factor, for the case where the TOTP device is gone.
//
// Like TOTP it requires a first factor: a recovery code is a backup for the
// second step, not a way to skip the first.
func (s *Service) AuthenticationVerifyRecoveryCode(
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
			fmt.Errorf("%w: a first factor must be verified before a recovery code", ErrTransactionClosed)
	}

	stored := s.recovery[transaction.PrincipalID]
	digests := make([]string, 0, len(stored.Unspent))
	for digest := range stored.Unspent {
		digests = append(digests, digest)
	}
	matched, found := authenticatordomain.MatchRecoveryCode(digests, code)

	if !found {
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

	// Spending the code is durable, so a second use is refused even after a
	// restart that loses in-memory state.
	used, err := s.ledger.Append(ctx, authenticatordomain.EventRecoveryCodeUsed,
		transaction.TenantID, actor,
		authenticatordomain.RecoveryCodeUsedPayload{
			PrincipalID: transaction.PrincipalID,
			TenantID:    transaction.TenantID,
			Digest:      matched,
		})
	if err != nil {
		return AuthenticationResult{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyRecoveryCodeUsed(used); err != nil {
		return AuthenticationResult{}, err
	}

	event, err := s.ledger.Append(ctx, authndomain.EventFactorVerified, transaction.TenantID, actor,
		authndomain.FactorVerifiedPayload{
			TransactionID: transactionID,
			TenantID:      transaction.TenantID,
			PrincipalID:   transaction.PrincipalID,
			Factor:        authndomain.FactorRecoveryCode,
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

func (s *Service) applyRecoveryCodesIssued(event audit.Event) error {
	var payload authenticatordomain.RecoveryCodesIssuedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	if _, exists := s.principals[payload.PrincipalID]; !exists {
		return fmt.Errorf("event sequence %d issues recovery codes for an unknown principal", event.Sequence)
	}
	if err := authenticatordomain.ValidateRecoveryDigests(payload.Digests); err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	unspent := make(map[string]struct{}, len(payload.Digests))
	for _, digest := range payload.Digests {
		unspent[digest] = struct{}{}
	}
	// A fresh issue replaces the previous set entirely.
	s.recovery[payload.PrincipalID] = recoveryCodes{Unspent: unspent}
	return nil
}

func (s *Service) applyRecoveryCodeUsed(event audit.Event) error {
	var payload authenticatordomain.RecoveryCodeUsedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	stored, exists := s.recovery[payload.PrincipalID]
	if !exists {
		return fmt.Errorf("event sequence %d spends a code for a principal with no set", event.Sequence)
	}
	// Spending an already-spent code during replay is not an error: the
	// ledger is the record, and deleting an absent key is a no-op. A second
	// live attempt is refused earlier, by the match failing.
	delete(stored.Unspent, payload.Digest)
	s.recovery[payload.PrincipalID] = stored
	return nil
}
