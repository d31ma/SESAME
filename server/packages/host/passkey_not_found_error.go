package host

// PasskeyNotFoundError reports a passkey credential that is unknown or that
// belongs to a principal other than the one the request acts on. Both answer
// the same, so a caller cannot learn which credential IDs exist.
type PasskeyNotFoundError struct{}

func (failure *PasskeyNotFoundError) Error() string {
	return "the passkey is unknown or belongs to another principal"
}

// ErrorCode returns passkey_not_found.
func (failure *PasskeyNotFoundError) ErrorCode() string {
	return "passkey_not_found"
}
