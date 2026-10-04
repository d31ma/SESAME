type ScimUser struct {
	ID          string `json:"id"`
	ExternalID  string `json:"externalId,omitempty"`
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName,omitempty"`
	Active      bool   `json:"active"`
}
