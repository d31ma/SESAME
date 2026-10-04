type OidcRefreshFamilyRevokeRequest struct {
	FamilyID string `json:"family_id"`
	Reason   string `json:"reason,omitempty"`
}
