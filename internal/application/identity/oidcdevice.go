package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	sessiondomain "github.com/d31ma/sesame/internal/domain/session"
)

// Stable device-grant errors.
var (
	// ErrDeviceAuthorizationNotFound covers unknown, expired, and
	// cross-tenant device authorizations alike.
	ErrDeviceAuthorizationNotFound = errors.New("device authorization not found")
	// ErrDeviceAuthorizationPending is the polling device's "not yet". It is
	// the only outcome that invites another poll.
	ErrDeviceAuthorizationPending = errors.New("the device authorization is still pending")
	// ErrDeviceSlowDown reports a device polling faster than the interval it
	// was given. RFC 8628 requires the device to add five seconds and keep
	// going, so this is guidance rather than a refusal.
	ErrDeviceSlowDown = errors.New("the device is polling faster than the interval")
	// ErrDeviceAccessDenied covers refusal, expiry, and a user code exhausted
	// by wrong guesses. One error for all three: a device that could tell
	// them apart could probe the verification surface through the token
	// endpoint.
	ErrDeviceAccessDenied = errors.New("the device authorization was denied")
	// ErrUserCodeNotFound reports a user code that matches no pending
	// authorization, including one whose attempts are spent.
	ErrUserCodeNotFound = errors.New("no pending device authorization for that user code")
)

// StartedDeviceAuthorization is what the device is told to display.
type StartedDeviceAuthorization struct {
	DeviceAuthorizationID string `json:"device_authorization_id"`
	// DeviceCode is returned exactly once and stored only as a digest.
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
	// Interval is the minimum gap between polls, in seconds.
	Interval  int    `json:"interval"`
	ExpiresAt string `json:"expires_at"`
	ExpiresIn int64  `json:"expires_in"`
}

// PendingDeviceAuthorization is what the verification surface shows a person
// before they approve: enough to decide, and nothing that identifies the
// device beyond the client asking.
type PendingDeviceAuthorization struct {
	DeviceAuthorizationID string   `json:"device_authorization_id"`
	ClientID              string   `json:"client_id"`
	ClientName            string   `json:"client_name"`
	Scopes                []string `json:"scopes"`
	ExpiresAt             string   `json:"expires_at"`
}

// DeviceAuthorizationStart validates a device's request and mints the pair of
// codes it needs: one it keeps, one it shows.
func (s *Service) DeviceAuthorizationStart(
	ctx context.Context,
	clientID string,
	scopes []string,
	actor string,
) (StartedDeviceAuthorization, error) {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return StartedDeviceAuthorization{}, err
	}
	if err := oidcdomain.ValidateClientID(clientID); err != nil {
		return StartedDeviceAuthorization{}, err
	}
	if err := oidcdomain.ValidateDeviceScopes(scopes); err != nil {
		return StartedDeviceAuthorization{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, exists := s.clients[clientID]
	if !exists || stored.Client.Disabled {
		// A disabled and an unknown client are one answer here for the same
		// reason as at the authorization endpoint: distinguishing them
		// enumerates registrations.
		return StartedDeviceAuthorization{}, ErrClientNotFound
	}
	granted, err := oidcdomain.NormalizeScopes(scopes)
	if err != nil {
		return StartedDeviceAuthorization{}, err
	}
	if allowed, offending := stored.Client.AllowsScopes(granted); !allowed {
		return StartedDeviceAuthorization{}, fmt.Errorf("%w: %s", ErrScopeNotAllowed, offending)
	}
	return s.openDeviceAuthorizationLocked(ctx, stored.Client, granted, actor)
}

func (s *Service) openDeviceAuthorizationLocked(
	ctx context.Context,
	client oidcdomain.Client,
	scopes []string,
	actor string,
) (StartedDeviceAuthorization, error) {
	id, err := oidcdomain.NewDeviceAuthorizationID()
	if err != nil {
		return StartedDeviceAuthorization{}, err
	}
	deviceCode, digest, err := oidcdomain.NewDeviceCode()
	if err != nil {
		return StartedDeviceAuthorization{}, err
	}
	userCode, err := s.uniqueUserCodeLocked()
	if err != nil {
		return StartedDeviceAuthorization{}, err
	}

	now := s.now()
	// This is the only moment the map grows, so it is the only moment it can
	// need shrinking. Without this the projection kept every authorization
	// ever started for the life of the process.
	s.pruneDeviceAuthorizationsLocked(now)
	expiresAt := now.Add(oidcdomain.DeviceCodeLifetime)
	event, err := s.ledger.Append(ctx, oidcdomain.EventDeviceAuthorizationStarted,
		client.TenantID, actor,
		oidcdomain.DeviceAuthorizationStartedPayload{
			DeviceAuthorizationID: id,
			TenantID:              client.TenantID,
			ClientID:              client.ID,
			Scopes:                scopes,
			UserCode:              userCode,
			CodeDigest:            digest,
			Interval:              oidcdomain.DevicePollInterval,
			AttemptsLeft:          oidcdomain.DeviceUserCodeAttempts,
			CreatedAt:             now.Format(time.RFC3339Nano),
			ExpiresAt:             expiresAt.Format(time.RFC3339Nano),
		})
	if err != nil {
		return StartedDeviceAuthorization{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyDeviceAuthorizationStarted(event); err != nil {
		return StartedDeviceAuthorization{}, err
	}
	s.writeSnapshotLocked(ctx, id)

	return StartedDeviceAuthorization{
		DeviceAuthorizationID: id,
		DeviceCode:            deviceCode,
		UserCode:              userCode,
		Interval:              oidcdomain.DevicePollInterval,
		ExpiresAt:             expiresAt.Format(time.RFC3339Nano),
		ExpiresIn:             int64(oidcdomain.DeviceCodeLifetime / time.Second),
	}, nil
}

// uniqueUserCodeLocked mints a user code no live authorization already holds.
//
// Collisions are rare at 34 bits but not impossible, and two pending requests
// sharing a code would make approval ambiguous — the worst possible outcome
// for a surface whose entire job is to bind a person's intent to one device.
func (s *Service) uniqueUserCodeLocked() (string, error) {
	now := s.now()
	for range 8 {
		candidate, err := oidcdomain.NewUserCode()
		if err != nil {
			return "", err
		}
		if _, taken := s.liveDeviceByUserCodeLocked(candidate, now); !taken {
			return candidate, nil
		}
	}
	return "", errors.New("could not mint an unused user code")
}

// liveDeviceByUserCodeLocked finds a pending, unexpired authorization by the
// code a person typed.
func (s *Service) liveDeviceByUserCodeLocked(
	userCode string,
	now time.Time,
) (oidcdomain.DeviceAuthorization, bool) {
	normalized := oidcdomain.NormalizeUserCode(userCode)
	for _, device := range s.deviceAuthorizations {
		if device.UserCode != normalized || device.Status != oidcdomain.DevicePending {
			continue
		}
		if device.Expired(now) {
			continue
		}
		return device, true
	}
	return oidcdomain.DeviceAuthorization{}, false
}

// DeviceAuthorizationLookup resolves a typed user code to the request a person
// is being asked to approve.
//
// A wrong code spends an attempt against the authorization it was aimed at —
// except that a wrong code by definition names no authorization, so there is
// nothing to charge. That asymmetry is why the lifetime is short: attempt
// bounding alone cannot stop a search across the whole code space, only a
// search against one request.
func (s *Service) DeviceAuthorizationLookup(
	tenantID, userCode string,
) (PendingDeviceAuthorization, error) {
	if err := oidcdomain.ValidateUserCode(userCode); err != nil {
		return PendingDeviceAuthorization{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	device, found := s.liveDeviceByUserCodeLocked(userCode, s.now())
	if !found || device.TenantID != tenantID {
		return PendingDeviceAuthorization{}, ErrUserCodeNotFound
	}
	return PendingDeviceAuthorization{
		DeviceAuthorizationID: device.ID,
		ClientID:              device.ClientID,
		ClientName:            s.clients[device.ClientID].Client.Name,
		Scopes:                device.Scopes,
		ExpiresAt:             device.ExpiresAt,
	}, nil
}

// DeviceAuthorizationApprove binds an authenticated session to a waiting
// device.
//
// The session is proved here rather than named, exactly as at the browser
// interaction endpoint: this is the moment a person's identity attaches to a
// device they are holding, and a caller that could merely assert a principal
// could attach any device to anyone.
func (s *Service) DeviceAuthorizationApprove(
	ctx context.Context,
	tenantID, userCode, sessionID, sessionSecret, actor string,
) (PendingDeviceAuthorization, error) {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return PendingDeviceAuthorization{}, err
	}
	if err := oidcdomain.ValidateUserCode(userCode); err != nil {
		return PendingDeviceAuthorization{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	device, found := s.liveDeviceByUserCodeLocked(userCode, now)
	if !found || device.TenantID != tenantID {
		return PendingDeviceAuthorization{}, ErrUserCodeNotFound
	}
	session, err := s.verifySessionLocked(sessionID, sessionSecret, now)
	if err != nil {
		return PendingDeviceAuthorization{}, err
	}
	if session.TenantID != device.TenantID {
		return PendingDeviceAuthorization{}, ErrUserCodeNotFound
	}
	// A device grant issues tokens for a client, so it is subject to the same
	// consent rule a browser flow is.
	if satisfied, _ := s.consentSatisfiedLocked(
		s.clients[device.ClientID].Client, session.PrincipalID, device.Scopes); !satisfied {
		return PendingDeviceAuthorization{}, ErrConsentRequired
	}
	return s.approveDeviceLocked(ctx, device, session, actor)
}

func (s *Service) approveDeviceLocked(
	ctx context.Context,
	device oidcdomain.DeviceAuthorization,
	session sessiondomain.Session,
	actor string,
) (PendingDeviceAuthorization, error) {
	event, err := s.ledger.Append(ctx, oidcdomain.EventDeviceAuthorizationApproved,
		device.TenantID, actor,
		oidcdomain.DeviceAuthorizationApprovedPayload{
			DeviceAuthorizationID: device.ID,
			TenantID:              device.TenantID,
			PrincipalID:           session.PrincipalID,
			SessionID:             session.ID,
			Assurance:             session.Assurance,
			ApprovedAt:            s.now().Format(time.RFC3339Nano),
		})
	if err != nil {
		return PendingDeviceAuthorization{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyDeviceAuthorizationApproved(event); err != nil {
		return PendingDeviceAuthorization{}, err
	}
	s.writeSnapshotLocked(ctx, device.ID)

	return PendingDeviceAuthorization{
		DeviceAuthorizationID: device.ID,
		ClientID:              device.ClientID,
		ClientName:            s.clients[device.ClientID].Client.Name,
		Scopes:                device.Scopes,
		ExpiresAt:             device.ExpiresAt,
	}, nil
}

// DeviceAuthorizationDeny records a person refusing a device.
//
// Denial is durable so the device stops polling for a reason that survives a
// restart, rather than being told "pending" forever by a rebuilt projection.
func (s *Service) DeviceAuthorizationDeny(
	ctx context.Context,
	tenantID, userCode, actor string,
) error {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return err
	}
	if err := oidcdomain.ValidateUserCode(userCode); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	device, found := s.liveDeviceByUserCodeLocked(userCode, s.now())
	if !found || device.TenantID != tenantID {
		return ErrUserCodeNotFound
	}
	return s.denyDeviceLocked(ctx, device, oidcdomain.DeviceDeniedByUser, actor)
}

func (s *Service) denyDeviceLocked(
	ctx context.Context,
	device oidcdomain.DeviceAuthorization,
	reason, actor string,
) error {
	event, err := s.ledger.Append(ctx, oidcdomain.EventDeviceAuthorizationDenied,
		device.TenantID, actor,
		oidcdomain.DeviceAuthorizationDeniedPayload{
			DeviceAuthorizationID: device.ID,
			TenantID:              device.TenantID,
			Reason:                reason,
			DeniedAt:              s.now().Format(time.RFC3339Nano),
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyDeviceAuthorizationDenied(event); err != nil {
		return err
	}
	s.writeSnapshotLocked(ctx, device.ID)
	return nil
}

// deviceCodeExchange is the polling device's half of the token endpoint.
//
// Every outcome here is deliberately narrow. "Pending" is the only one that
// invites another poll; everything else is terminal, and the terminal ones
// collapse into one error so the device cannot distinguish "refused" from
// "expired" from "never existed".
func (s *Service) deviceCodeExchange(
	ctx context.Context,
	request TokenRequest,
	actor string,
) (TokenResponse, error) {
	client, err := s.clientForTokenRequest(request)
	if err != nil {
		return TokenResponse{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	device, found := s.deviceByCodeLocked(request.DeviceCode)
	if !found || device.ClientID != client.ID {
		// A device code that names no authorization, or one belonging to a
		// different client, is indistinguishable from a wrong guess.
		return TokenResponse{}, ErrInvalidGrant
	}

	now := s.now()
	switch {
	case device.Status == oidcdomain.DeviceRedeemed:
		// Single use. A second exchange is a replay, not a slow device.
		return TokenResponse{}, ErrInvalidGrant
	case device.Status == oidcdomain.DeviceDenied:
		return TokenResponse{}, ErrDeviceAccessDenied
	case device.Expired(now):
		// Expiry is recorded rather than merely computed, so the reason is in
		// the ledger and a later poll is refused for a known cause.
		if err := s.denyDeviceLocked(ctx, device, oidcdomain.DeviceDeniedExpired, actor); err != nil {
			return TokenResponse{}, err
		}
		return TokenResponse{}, ErrDeviceAccessDenied
	case device.Status == oidcdomain.DevicePending:
		return TokenResponse{}, ErrDeviceAuthorizationPending
	}
	return s.redeemDeviceLocked(ctx, request, device, client, now, actor)
}

func (s *Service) redeemDeviceLocked(
	ctx context.Context,
	request TokenRequest,
	device oidcdomain.DeviceAuthorization,
	client oidcClientRecord,
	now time.Time,
	actor string,
) (TokenResponse, error) {
	// The session that approved the device must still be usable. Otherwise a
	// person could approve a device, sign out, and have the device collect
	// tokens afterwards.
	session, exists := s.sessions[device.SessionID]
	if !exists || !session.Active(now) {
		return TokenResponse{}, ErrDeviceAccessDenied
	}

	event, err := s.ledger.Append(ctx, oidcdomain.EventDeviceCodeRedeemed,
		device.TenantID, actor,
		oidcdomain.DeviceCodeRedeemedPayload{
			DeviceAuthorizationID: device.ID,
			TenantID:              device.TenantID,
			RedeemedAt:            now.Format(time.RFC3339Nano),
		})
	if err != nil {
		return TokenResponse{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyDeviceCodeRedeemed(event); err != nil {
		return TokenResponse{}, err
	}

	thumbprint, err := s.tokenRequestThumbprint(ctx, request, device.TenantID, actor)
	if err != nil {
		return TokenResponse{}, err
	}

	// No nonce: a device grant attests to an approval that already happened,
	// not to a fresh authentication event bound to a browser request.
	response, err := s.issueTokensLocked(ctx, grantSubject{
		TenantID:    device.TenantID,
		ClientID:    client.ID,
		PrincipalID: device.PrincipalID,
		SessionID:   device.SessionID,
		Scopes:      device.Scopes,
		Assurance:   device.Assurance,
		TokenID:     device.ID,
		Thumbprint:  thumbprint,
		// An empty family ID starts a new rotating family, which is what
		// establishes its lifetime ceiling. Naming one here would read as
		// continuing a family that never existed.
	}, "", now, actor)
	if err != nil {
		return TokenResponse{}, err
	}
	s.writeSnapshotLocked(ctx, device.ID)
	return response, nil
}

// deviceByCodeLocked resolves a presented device code to its authorization.
func (s *Service) deviceByCodeLocked(code string) (oidcdomain.DeviceAuthorization, bool) {
	if strings.TrimSpace(code) == "" {
		return oidcdomain.DeviceAuthorization{}, false
	}
	digest := oidcdomain.Digest(code)
	for _, device := range s.deviceAuthorizations {
		if device.CodeDigest != "" && oidcdomain.VerifyDigest(device.CodeDigest, code) {
			return device, true
		}
		// A spent authorization has its digest cleared, so match the
		// remembered one to tell a replay or a refusal from an unknown code.
		if device.CodeDigest == "" && device.SpentDigest == digest {
			return device, true
		}
	}
	return oidcdomain.DeviceAuthorization{}, false
}
