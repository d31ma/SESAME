package host

import (
	"errors"
	"fmt"
	"testing"
)

func TestEveryHostErrorNamesItsCode(t *testing.T) {
	cases := map[string]CodedError{
		"engine_busy":               &EngineBusyError{},
		"engine_not_configured":     &EngineNotConfiguredError{},
		"passkey_not_found":         &PasskeyNotFoundError{},
		"reauthentication_required": &ReauthenticationRequiredError{},
		"session_rejected":          &SessionRejectedError{},
		"tenant_mismatch":           &TenantMismatchError{},
	}
	for code, failure := range cases {
		var coded CodedError
		if !errors.As(fmt.Errorf("wrapped: %w", failure), &coded) {
			t.Fatalf("%T is not found as a CodedError through wrapping", failure)
		}
		if coded.ErrorCode() != code {
			t.Errorf("%T.ErrorCode() = %q, want %q", failure, coded.ErrorCode(), code)
		}
		if failure.Error() == "" {
			t.Errorf("%T.Error() is empty", failure)
		}
	}
}
