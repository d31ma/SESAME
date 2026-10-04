// @RequestRoute("/api/v1/token")
// @NeedsAll
type TokenController struct {
	publicCallService *PublicCallService
}

// @PostRoute("/jwks")
// @Public
func (controller *TokenController) PostJwks() (TokenKeySet, error) {
	var result TokenKeySet
	err := controller.publicCallService.Call(EngineCall{Operation: "token.jwks", Parameters: struct{}{}, Result: &result})
	return result, err
}
