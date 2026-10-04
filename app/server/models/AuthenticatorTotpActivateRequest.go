type AuthenticatorTotpActivateRequest struct {
	PrincipalID string `json:"principal_id"`
	Code        string `json:"code"`
}
