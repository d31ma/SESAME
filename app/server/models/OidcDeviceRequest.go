type OidcDeviceRequest struct {
	DeviceAuthorizationID string   `json:"device_authorization_id"`
	ClientID              string   `json:"client_id"`
	ClientName            string   `json:"client_name"`
	Scopes                []string `json:"scopes"`
	ExpiresAt             string   `json:"expires_at"`
}
