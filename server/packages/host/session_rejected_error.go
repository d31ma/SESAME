package host

// SessionRejectedError reports a Sesame-Session credential that is missing,
// malformed, unknown, expired or revoked.
type SessionRejectedError struct{}

func (failure *SessionRejectedError) Error() string {
	return "the Sesame-Session credential is missing, malformed, unknown, expired or revoked"
}

// ErrorCode returns session_rejected.
func (failure *SessionRejectedError) ErrorCode() string {
	return "session_rejected"
}
