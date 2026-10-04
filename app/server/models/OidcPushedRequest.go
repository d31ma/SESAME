type OidcPushedRequest struct {
	RequestAddress string `json:"request_uri"`
	ExpiresIn      int64  `json:"expires_in"`
}
