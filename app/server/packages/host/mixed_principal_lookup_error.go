package host

// MixedPrincipalLookupError reports a principal lookup that names a
// principal ID together with a tenant or identifier. A lookup by ID is
// isolated by the principal's own tenant, so the other fields are refused
// rather than ignored.
type MixedPrincipalLookupError struct{}

func (failure *MixedPrincipalLookupError) Error() string {
	return "name either principal_id or tenant_id with identifier_namespace and identifier_value, not both"
}

// ErrorCode returns invalid_request.
func (failure *MixedPrincipalLookupError) ErrorCode() string {
	return "invalid_request"
}
