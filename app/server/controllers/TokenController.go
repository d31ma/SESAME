// @RequestRoute("/api/v1/token")
// @NeedsAll
type TokenController struct {
	engineService *EngineService
}

// @PostRoute("/jwks")
// @Public
func (controller *TokenController) PostJwks() (TokenKeySet, error) {
	var result TokenKeySet
	err := controller.engineService.Call("token.jwks", struct{}{}, &result)
	return result, err
}
