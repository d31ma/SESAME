type FederationProviderRegisterRequest struct {
	TenantID     string   `json:"tenant_id"`
	Name         string   `json:"name"`
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	SubjectClaim string   `json:"subject_claim,omitempty"`
	EmailClaim   string   `json:"email_claim,omitempty"`
	Linking      string   `json:"linking,omitempty"`
}
