type AuthnPasskeyOptions struct {
	TransactionID         string   `json:"transaction_id"`
	Challenge             string   `json:"challenge"`
	RelyingPartyID        string   `json:"relying_party_id"`
	Origin                string   `json:"origin"`
	CredentialIdentifiers []string `json:"credential_ids"`
}
