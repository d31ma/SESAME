package host

// AdministratorRequiredError reports an administrative call made by a caller
// whose session does not hold the Administrator role in its tenant. The host
// decides the role again inside every administrative call, so the answer does
// not depend on the route guard having run.
type AdministratorRequiredError struct{}

func (failure *AdministratorRequiredError) Error() string {
	return "the caller's session is not an administrator of its tenant"
}

// ErrorCode returns administrator_required.
func (failure *AdministratorRequiredError) ErrorCode() string {
	return "administrator_required"
}
