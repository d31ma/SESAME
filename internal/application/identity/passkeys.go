package identity

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/d31ma/sesame/internal/domain/audit"
	authndomain "github.com/d31ma/sesame/internal/domain/authentication"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
)

// Stable passkey errors.
var (
	ErrPasskeyNotFound = errors.New("passkey not found")
	ErrPasskeyExists   = errors.New("this credential is already registered")
	// ErrNoRelyingParty reports passkey work attempted without an issuer to
	// derive the relying party from. A passkey is bound to a domain, so
	// there is nothing to bind it to.
	ErrNoRelyingParty = errors.New("no issuer is configured; a passkey must be bound to a relying party domain")
	// ErrPasskeyChallengeExpired reports a registration challenge that no
	// longer exists. Retrying costs one round trip.
	ErrPasskeyChallengeExpired = errors.New("passkey registration challenge has expired; begin again")
)

// PasskeyRegistrationChallengeLifetime bounds how long a user has to touch
// their authenticator.
const PasskeyRegistrationChallengeLifetime = 5 * time.Minute

// pendingPasskeyChallenge is one outstanding registration challenge.
//
// These are deliberately in-memory only. A challenge is a nonce whose whole
// job is to be unrepeatable; losing it on restart costs the user one retry,
// while a durable one would put an event in the ledger for every abandoned
// registration attempt. Nothing about a lost challenge is unsafe — an
// assertion against a challenge the engine no longer holds simply fails.
type pendingPasskeyChallenge struct {
	Challenge string
	ExpiresAt time.Time
}

// PasskeyRegistrationRequest is what a browser needs to create a credential.
type PasskeyRegistrationRequest struct {
	PrincipalID    string `json:"principal_id"`
	Challenge      string `json:"challenge"`
	RelyingPartyID string `json:"relying_party_id"`
	Origin         string `json:"origin"`
	ExpiresAt      string `json:"expires_at"`
}

// PasskeyAuthenticationRequest is what a browser needs to produce an
// assertion. The challenge belongs to the authentication transaction.
type PasskeyAuthenticationRequest struct {
	TransactionID  string `json:"transaction_id"`
	Challenge      string `json:"challenge"`
	RelyingPartyID string `json:"relying_party_id"`
	Origin         string `json:"origin"`
	// CredentialIDs lets a browser pick among the principal's registered
	// credentials. It is not secret: possession of the private key is what
	// authenticates, and the transaction already names the principal.
	CredentialIDs []string `json:"credential_ids"`
}

// relyingPartyLocked derives the WebAuthn relying party from the configured
// issuer. Origin is the issuer itself; RP ID is its host.
func (s *Service) relyingPartyLocked() (relyingParty string, origin string, err error) {
	if s.issuer == "" {
		return "", "", ErrNoRelyingParty
	}
	relyingParty, err = authenticatordomain.RelyingPartyID(s.issuer)
	if err != nil {
		return "", "", err
	}
	return relyingParty, s.issuer, nil
}

// PasskeyRegisterBegin issues a challenge for one principal.
func (s *Service) PasskeyRegisterBegin(principalID string) (PasskeyRegistrationRequest, error) {
	if err := principaldomain.ValidateID(principalID); err != nil {
		return PasskeyRegistrationRequest{}, err
	}
	challenge, err := authenticatordomain.NewPasskeyChallenge()
	if err != nil {
		return PasskeyRegistrationRequest{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	relyingParty, origin, err := s.relyingPartyLocked()
	if err != nil {
		return PasskeyRegistrationRequest{}, err
	}
	principal, exists := s.principals[principalID]
	if !exists || principal.Status != principaldomain.StatusActive {
		return PasskeyRegistrationRequest{}, ErrPrincipalNotFound
	}

	expiry := s.now().Add(PasskeyRegistrationChallengeLifetime)
	// One outstanding challenge per principal: beginning again replaces the
	// previous one rather than leaving both usable.
	s.passkeyChallenges[principalID] = pendingPasskeyChallenge{Challenge: challenge, ExpiresAt: expiry}
	return PasskeyRegistrationRequest{
		PrincipalID:    principalID,
		Challenge:      challenge,
		RelyingPartyID: relyingParty,
		Origin:         origin,
		ExpiresAt:      expiry.Format(time.RFC3339Nano),
	}, nil
}

// PasskeyRegisterFinish verifies an attestation and stores the credential.
func (s *Service) PasskeyRegisterFinish(
	ctx context.Context,
	principalID string,
	attestationObject []byte,
	clientDataJSON []byte,
	actor string,
) (authenticatordomain.Passkey, error) {
	if err := s.requireLedger(); err != nil {
		return authenticatordomain.Passkey{}, err
	}
	if err := principaldomain.ValidateID(principalID); err != nil {
		return authenticatordomain.Passkey{}, err
	}
	if actor == "" {
		return authenticatordomain.Passkey{}, errors.New("actor is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	relyingParty, origin, err := s.relyingPartyLocked()
	if err != nil {
		return authenticatordomain.Passkey{}, err
	}
	principal, exists := s.principals[principalID]
	if !exists || principal.Status != principaldomain.StatusActive {
		return authenticatordomain.Passkey{}, ErrPrincipalNotFound
	}
	pending, held := s.passkeyChallenges[principalID]
	if !held || !s.now().Before(pending.ExpiresAt) {
		delete(s.passkeyChallenges, principalID)
		return authenticatordomain.Passkey{}, ErrPasskeyChallengeExpired
	}
	// The challenge is spent whatever happens next. A failed attestation
	// must not leave a live challenge for a second try with different bytes.
	delete(s.passkeyChallenges, principalID)

	registered, err := authenticatordomain.VerifyPasskeyRegistration(
		attestationObject, clientDataJSON, pending.Challenge, origin, relyingParty)
	if err != nil {
		return authenticatordomain.Passkey{}, err
	}
	if _, taken := s.passkeys[registered.CredentialID]; taken {
		return authenticatordomain.Passkey{}, ErrPasskeyExists
	}

	event, err := s.ledger.Append(ctx, authenticatordomain.EventPasskeyRegistered, principal.TenantID, actor,
		authenticatordomain.PasskeyRegisteredPayload{
			CredentialID: registered.CredentialID,
			PrincipalID:  principalID,
			TenantID:     principal.TenantID,
			PublicKey:    registered.PublicKey,
			SignCount:    registered.SignCount,
			UserVerified: registered.UserVerified,
			RegisteredAt: s.now().Format(time.RFC3339Nano),
		})
	if err != nil {
		return authenticatordomain.Passkey{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyPasskeyRegistered(event); err != nil {
		return authenticatordomain.Passkey{}, err
	}
	s.writeSnapshotLocked(ctx, registered.CredentialID)
	return s.passkeys[registered.CredentialID], nil
}

// PasskeyList returns a principal's registered credentials. None of them
// carries private material — a public key and a counter are all that is
// stored.
func (s *Service) PasskeyList(principalID string) ([]authenticatordomain.Passkey, error) {
	if err := principaldomain.ValidateID(principalID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.passkeysForLocked(principalID), nil
}

func (s *Service) passkeysForLocked(principalID string) []authenticatordomain.Passkey {
	found := make([]authenticatordomain.Passkey, 0, 2)
	for _, passkey := range s.passkeys {
		if passkey.PrincipalID == principalID {
			found = append(found, passkey)
		}
	}
	sort.Slice(found, func(left, right int) bool {
		return found[left].CredentialID < found[right].CredentialID
	})
	return found
}

// PasskeyAuthenticationOptions returns what a browser needs to answer a
// passkey challenge for an in-flight transaction.
func (s *Service) PasskeyAuthenticationOptions(transactionID string) (PasskeyAuthenticationRequest, error) {
	if err := authndomain.ValidateID(transactionID); err != nil {
		return PasskeyAuthenticationRequest{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	relyingParty, origin, err := s.relyingPartyLocked()
	if err != nil {
		return PasskeyAuthenticationRequest{}, err
	}
	transaction, exists := s.transactions[transactionID]
	if !exists {
		return PasskeyAuthenticationRequest{}, ErrTransactionNotFound
	}
	if allowed, _ := transaction.CanAttempt(s.now()); !allowed {
		return PasskeyAuthenticationRequest{}, ErrTransactionClosed
	}

	credentials := make([]string, 0, 2)
	for _, passkey := range s.passkeysForLocked(transaction.PrincipalID) {
		credentials = append(credentials, passkey.CredentialID)
	}
	return PasskeyAuthenticationRequest{
		TransactionID:  transactionID,
		Challenge:      transaction.PasskeyChallenge,
		RelyingPartyID: relyingParty,
		Origin:         origin,
		CredentialIDs:  credentials,
	}, nil
}

// AuthenticationVerifyPasskey advances a transaction with a passkey
// assertion.
//
// Unlike TOTP and recovery codes, a passkey needs no prior factor: it proves
// possession of a private key that never left the authenticator, and when the
// authenticator also verified the user it establishes MFA on its own. That is
// the whole point of a phishing-resistant credential — requiring a password
// first would reintroduce the thing being replaced.
func (s *Service) AuthenticationVerifyPasskey(
	ctx context.Context,
	transactionID string,
	credentialID string,
	authenticatorData []byte,
	clientDataJSON []byte,
	signature []byte,
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

	relyingParty, origin, err := s.relyingPartyLocked()
	if err != nil {
		return AuthenticationResult{}, err
	}
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

	// A credential registered to somebody else proves nothing about this
	// transaction's principal, so it is treated exactly like a wrong one.
	stored, registered := s.passkeys[credentialID]
	matched := false
	var asserted authenticatordomain.AssertedPasskey
	if registered && stored.PrincipalID == transaction.PrincipalID && transaction.PrincipalID != "" {
		asserted, err = authenticatordomain.VerifyPasskeyAssertion(
			stored, authenticatorData, clientDataJSON, signature,
			transaction.PasskeyChallenge, origin, relyingParty)
		matched = err == nil
	}

	if !matched {
		attempts := transaction.Attempts + 1
		failure := authndomain.ReasonInvalidCredentials
		if attempts >= authndomain.MaxAttempts {
			failure = authndomain.ReasonAttemptsExhausted
		}
		event, appendErr := s.ledger.Append(ctx, authndomain.EventFailed, transaction.TenantID, actor,
			authndomain.FailedPayload{
				TransactionID: transactionID,
				TenantID:      transaction.TenantID,
				Reason:        failure,
				Attempts:      attempts,
			})
		if appendErr != nil {
			return AuthenticationResult{}, fmt.Errorf("%w: %v", ErrStorageFailure, appendErr)
		}
		if err := s.applyAuthenticationFailed(event); err != nil {
			return AuthenticationResult{}, err
		}
		s.writeSnapshotLocked(ctx, transactionID)
		return s.authenticationResultLocked(transactionID), nil
	}

	// The advanced counter is durable, so a cloned authenticator is still
	// detected after a restart.
	used, err := s.ledger.Append(ctx, authenticatordomain.EventPasskeyUsed, transaction.TenantID, actor,
		authenticatordomain.PasskeyUsedPayload{
			CredentialID: credentialID,
			PrincipalID:  stored.PrincipalID,
			TenantID:     stored.TenantID,
			SignCount:    asserted.SignCount,
			UserVerified: asserted.UserVerified,
		})
	if err != nil {
		return AuthenticationResult{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyPasskeyUsed(used); err != nil {
		return AuthenticationResult{}, err
	}

	// A verified user plus a possessed key is two factors in one gesture.
	// Without user verification it is possession alone.
	assurance := authndomain.AssurancePassword
	if asserted.UserVerified {
		assurance = authndomain.AssuranceMFA
	}
	event, err := s.ledger.Append(ctx, authndomain.EventFactorVerified, transaction.TenantID, actor,
		authndomain.FactorVerifiedPayload{
			TransactionID: transactionID,
			TenantID:      transaction.TenantID,
			PrincipalID:   transaction.PrincipalID,
			Factor:        authndomain.FactorPasskey,
			Assurance:     assurance,
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

// PasskeyRemove durably unregisters a credential — the lost-device response.
func (s *Service) PasskeyRemove(ctx context.Context, credentialID, actor string) error {
	if err := s.requireLedger(); err != nil {
		return err
	}
	if err := authenticatordomain.ValidateCredentialID(credentialID); err != nil {
		return err
	}
	if actor == "" {
		return errors.New("actor is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, exists := s.passkeys[credentialID]
	if !exists {
		return ErrPasskeyNotFound
	}
	event, err := s.ledger.Append(ctx, authenticatordomain.EventPasskeyRemoved, stored.TenantID, actor,
		authenticatordomain.PasskeyRemovedPayload{
			CredentialID: credentialID,
			PrincipalID:  stored.PrincipalID,
			TenantID:     stored.TenantID,
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyPasskeyRemoved(event); err != nil {
		return err
	}
	s.writeSnapshotLocked(ctx, credentialID)
	return nil
}

func (s *Service) applyPasskeyRegistered(event audit.Event) error {
	var payload authenticatordomain.PasskeyRegisteredPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	if _, exists := s.principals[payload.PrincipalID]; !exists {
		return fmt.Errorf("event sequence %d registers a passkey for an unknown principal", event.Sequence)
	}
	if err := authenticatordomain.ValidateCredentialID(payload.CredentialID); err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	if _, exists := s.passkeys[payload.CredentialID]; exists {
		return fmt.Errorf("event sequence %d registers a duplicate credential", event.Sequence)
	}
	s.passkeys[payload.CredentialID] = authenticatordomain.Passkey{
		CredentialID: payload.CredentialID,
		PrincipalID:  payload.PrincipalID,
		TenantID:     payload.TenantID,
		PublicKey:    payload.PublicKey,
		SignCount:    payload.SignCount,
		UserVerified: payload.UserVerified,
		RegisteredAt: payload.RegisteredAt,
	}
	return nil
}

func (s *Service) applyPasskeyUsed(event audit.Event) error {
	var payload authenticatordomain.PasskeyUsedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	stored, exists := s.passkeys[payload.CredentialID]
	if !exists || stored.PrincipalID != payload.PrincipalID {
		return fmt.Errorf("event sequence %d uses an unknown credential", event.Sequence)
	}
	stored.SignCount = payload.SignCount
	s.passkeys[payload.CredentialID] = stored
	return nil
}

func (s *Service) applyPasskeyRemoved(event audit.Event) error {
	var payload authenticatordomain.PasskeyRemovedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	stored, exists := s.passkeys[payload.CredentialID]
	if !exists || stored.PrincipalID != payload.PrincipalID {
		return fmt.Errorf("event sequence %d removes an unknown credential", event.Sequence)
	}
	delete(s.passkeys, payload.CredentialID)
	return nil
}

func (s *Service) admitPasskey(passkey authenticatordomain.Passkey) error {
	if err := authenticatordomain.ValidateCredentialID(passkey.CredentialID); err != nil {
		return err
	}
	if _, exists := s.principals[passkey.PrincipalID]; !exists {
		return fmt.Errorf("passkey %s belongs to an unknown principal", passkey.CredentialID)
	}
	if _, exists := s.passkeys[passkey.CredentialID]; exists {
		return errors.New("duplicate credential ID")
	}
	s.passkeys[passkey.CredentialID] = passkey
	return nil
}
