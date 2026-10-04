type AuthenticatorPasskeyChallenge struct {
	PrincipalID    string `json:"principal_id"`
	Challenge      string `json:"challenge"`
	RelyingPartyID string `json:"relying_party_id"`
	Origin         string `json:"origin"`
	ExpiresAt      string `json:"expires_at"`
}
