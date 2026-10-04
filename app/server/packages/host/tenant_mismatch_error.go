package host

// TenantMismatchError reports a request for a tenant other than the tenant
// of the caller's session.
type TenantMismatchError struct{}

func (failure *TenantMismatchError) Error() string {
	return "the request names a tenant other than the caller's session tenant"
}

// ErrorCode returns tenant_mismatch.
func (failure *TenantMismatchError) ErrorCode() string {
	return "tenant_mismatch"
}
