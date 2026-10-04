type AuthenticatorPasskeyRegisterFinishRequest struct {
	PrincipalID       string `json:"principal_id"`
	AttestationObject string `json:"attestation_object"`
	ClientDataJSON    string `json:"client_data_json"`
}
