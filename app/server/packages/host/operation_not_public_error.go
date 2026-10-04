package host

// OperationNotPublicError reports an operation sent through the host's
// public call path that no public route is meant to reach. It is a host
// programming error, not a client error, so it answers 500 internal_error
// and the engine never runs.
type OperationNotPublicError struct{}

func (failure *OperationNotPublicError) Error() string {
	return "the host refused to send a non-public operation through its public call path"
}

// ErrorCode returns operation_not_public.
func (failure *OperationNotPublicError) ErrorCode() string {
	return "operation_not_public"
}
