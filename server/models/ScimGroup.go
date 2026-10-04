type ScimGroup struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"displayName"`
	Members     []string `json:"members"`
}
