package host

// ReauthenticationRequiredError reports a self-service authenticator change
// made with a session that was issued too long ago. The caller must sign in
// again and retry with the new session.
type ReauthenticationRequiredError struct{}

func (failure *ReauthenticationRequiredError) Error() string {
	return "sign in again: changing an authenticator needs a recently issued session"
}

// ErrorCode returns reauthentication_required.
func (failure *ReauthenticationRequiredError) ErrorCode() string {
	return "reauthentication_required"
}
