type FederatedLoginResult struct {
	Session     FederatedSession `json:"session"`
	PrincipalID string           `json:"principal_id"`
	Provisioned bool             `json:"provisioned,omitempty"`
}
