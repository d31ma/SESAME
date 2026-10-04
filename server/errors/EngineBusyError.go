type EngineBusyError struct{}

func (failure *EngineBusyError) Error() string {
	return "another SESAME engine holds the deployment; try again later"
}
