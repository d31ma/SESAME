type AuthnPasskeyOptions struct {
	TransactionID  string   `json:"transaction_id"`
	Challenge      string   `json:"challenge"`
	RelyingPartyID string   `json:"relying_party_id"`
	Origin         string   `json:"origin"`
	CredentialIDs  []string `json:"credential_ids"`
}
