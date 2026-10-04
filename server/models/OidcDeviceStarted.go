type OidcDeviceStarted struct {
	DeviceAuthorizationID string `json:"device_authorization_id"`
	DeviceCode            string `json:"device_code"`
	UserCode              string `json:"user_code"`
	Interval              int64  `json:"interval"`
	ExpiresAt             string `json:"expires_at"`
	ExpiresIn             int64  `json:"expires_in"`
}
