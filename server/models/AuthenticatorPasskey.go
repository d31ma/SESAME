type AuthenticatorPasskey struct {
	CredentialID string `json:"credential_id"`
	PrincipalID  string `json:"principal_id"`
	TenantID     string `json:"tenant_id"`
	PublicKey    string `json:"public_key"`
	SignCount    uint32 `json:"sign_count"`
	UserVerified bool   `json:"user_verified"`
	RegisteredAt string `json:"registered_at"`
}
