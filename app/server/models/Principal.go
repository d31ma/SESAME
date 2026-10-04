type Principal struct {
	PrincipalID string              `json:"principal_id"`
	TenantID    string              `json:"tenant_id"`
	Kind        string              `json:"kind"`
	Status      string              `json:"status"`
	Identifier  PrincipalIdentifier `json:"identifier"`
}
