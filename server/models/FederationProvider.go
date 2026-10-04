type FederationProvider struct {
	ProviderID   string   `json:"provider_id"`
	TenantID     string   `json:"tenant_id"`
	Name         string   `json:"name"`
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	Scopes       []string `json:"scopes"`
	SubjectClaim string   `json:"subject_claim"`
	EmailClaim   string   `json:"email_claim,omitempty"`
	Linking      string   `json:"linking"`
	Disabled     bool     `json:"disabled,omitempty"`
}
