type OidcDpopVerifyRequest struct {
	AccessToken string `json:"access_token"`
	Proof       string `json:"dpop_proof"`
	Method      string `json:"http_method"`
	Address     string `json:"http_uri"`
}
