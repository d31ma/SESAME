type AuthenticatorTotpEnrollRequest struct {
	PrincipalID string `json:"principal_id"`
	Issuer      string `json:"issuer,omitempty"`
}
