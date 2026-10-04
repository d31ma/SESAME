package host

// EngineBusyError reports that another engine owned the deployment for the
// whole configured wait. Nothing ran, so the request may be retried.
type EngineBusyError struct{}

func (failure *EngineBusyError) Error() string {
	return "another SESAME engine owns the deployment; try again later"
}

// ErrorCode returns engine_busy.
func (failure *EngineBusyError) ErrorCode() string {
	return "engine_busy"
}
