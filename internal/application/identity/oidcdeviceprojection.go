package identity

import (
	"fmt"
	"sort"
	"time"

	"github.com/d31ma/sesame/internal/domain/audit"
	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
)

// DeviceAuthorizationState is one device grant in a snapshot.
//
// The whole record travels, including the user code and the code digest. A
// device polls across restarts by definition — that is the shape of the grant
// — so a projection that forgot one would strand every device mid-flow.
type DeviceAuthorizationState struct {
	Device oidcdomain.DeviceAuthorization `json:"device"`
}

func (s *Service) applyDeviceAuthorizationStarted(event audit.Event) error {
	var payload oidcdomain.DeviceAuthorizationStartedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	s.deviceAuthorizations[payload.DeviceAuthorizationID] = oidcdomain.DeviceAuthorization{
		ID:           payload.DeviceAuthorizationID,
		TenantID:     payload.TenantID,
		ClientID:     payload.ClientID,
		Scopes:       payload.Scopes,
		UserCode:     payload.UserCode,
		Status:       oidcdomain.DevicePending,
		AttemptsLeft: payload.AttemptsLeft,
		Interval:     payload.Interval,
		CreatedAt:    payload.CreatedAt,
		ExpiresAt:    payload.ExpiresAt,
		CodeDigest:   payload.CodeDigest,
	}
	return nil
}

func (s *Service) applyDeviceAuthorizationApproved(event audit.Event) error {
	var payload oidcdomain.DeviceAuthorizationApprovedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	device, exists := s.deviceAuthorizations[payload.DeviceAuthorizationID]
	if !exists {
		return nil
	}
	device.Status = oidcdomain.DeviceApproved
	device.PrincipalID = payload.PrincipalID
	device.SessionID = payload.SessionID
	device.Assurance = payload.Assurance
	s.deviceAuthorizations[payload.DeviceAuthorizationID] = device
	return nil
}

func (s *Service) applyDeviceAuthorizationDenied(event audit.Event) error {
	var payload oidcdomain.DeviceAuthorizationDeniedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	device, exists := s.deviceAuthorizations[payload.DeviceAuthorizationID]
	if !exists {
		return nil
	}
	device.Status = oidcdomain.DeviceDenied
	device.DeniedReason = payload.Reason
	// The digest moves rather than vanishing: a device polling a refused
	// authorization must be told it was denied, not that its code is unknown.
	device.SpentDigest = device.CodeDigest
	device.CodeDigest = ""
	s.deviceAuthorizations[payload.DeviceAuthorizationID] = device
	return nil
}

func (s *Service) applyDeviceCodeRedeemed(event audit.Event) error {
	var payload oidcdomain.DeviceCodeRedeemedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	device, exists := s.deviceAuthorizations[payload.DeviceAuthorizationID]
	if !exists {
		return nil
	}
	device.Status = oidcdomain.DeviceRedeemed
	// The digest moves rather than vanishing: a second exchange has to be
	// refused as a replay, which needs the code to still be recognisable.
	device.SpentDigest = device.CodeDigest
	device.CodeDigest = ""
	s.deviceAuthorizations[payload.DeviceAuthorizationID] = device
	return nil
}

func (s *Service) admitDeviceAuthorization(restored DeviceAuthorizationState) error {
	if err := oidcdomain.ValidateDeviceAuthorizationID(restored.Device.ID); err != nil {
		return err
	}
	s.deviceAuthorizations[restored.Device.ID] = restored.Device
	return nil
}

func (s *Service) exportDeviceAuthorizationsLocked() []DeviceAuthorizationState {
	// Expired grants are dropped rather than carried forever: a device grant
	// has a ten-minute life, so anything past it is dead weight in every
	// future snapshot.
	now := s.now()
	devices := make([]DeviceAuthorizationState, 0, len(s.deviceAuthorizations))
	for _, device := range s.deviceAuthorizations {
		if device.Expired(now) && device.Status != oidcdomain.DeviceRedeemed {
			continue
		}
		devices = append(devices, DeviceAuthorizationState{Device: device})
	}
	sort.Slice(devices, func(left, right int) bool {
		return devices[left].Device.ID < devices[right].Device.ID
	})
	return devices
}

// deviceAuthorizationRetention keeps a redeemed grant around long enough for a
// replayed device code to be refused as a replay rather than as an unknown
// code. Beyond the grant's own lifetime there is nothing left to replay.
const deviceAuthorizationRetention = 2 * oidcdomain.DeviceCodeLifetime

// pruneDeviceAuthorizationsLocked drops records past any possible use.
func (s *Service) pruneDeviceAuthorizationsLocked(now time.Time) {
	for id, device := range s.deviceAuthorizations {
		deadline, err := time.Parse(time.RFC3339Nano, device.ExpiresAt)
		if err != nil || now.Sub(deadline) > deviceAuthorizationRetention {
			delete(s.deviceAuthorizations, id)
		}
	}
}
