type AuthnVerifyPasskeyRequest struct {
	TransactionID     string `json:"transaction_id"`
	CredentialID      string `json:"credential_id"`
	AuthenticatorData string `json:"authenticator_data"`
	ClientDataJSON    string `json:"client_data_json"`
	Signature         string `json:"signature"`
}
