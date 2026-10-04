type ScimGroupList struct {
	TotalResults int         `json:"totalResults"`
	StartIndex   int         `json:"startIndex"`
	ItemsPerPage int         `json:"itemsPerPage"`
	Resources    []ScimGroup `json:"Resources"`
}
