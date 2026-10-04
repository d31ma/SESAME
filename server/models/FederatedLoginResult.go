type FederatedLoginResult struct {
	Session     AuthnIssuedSession `json:"session"`
	PrincipalID string             `json:"principal_id"`
	Provisioned bool               `json:"provisioned,omitempty"`
}
