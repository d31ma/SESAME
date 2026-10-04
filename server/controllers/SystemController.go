import "net/http"

// @RequestRoute("/api/v1/system")
// @NeedsAll
type SystemController struct {
	engineService     *EngineService
	tenantCallService *TenantCallService
}

// @PostRoute("/ping")
// @Public
func (controller *SystemController) PostPing() (SystemPing, error) {
	var result SystemPing
	err := controller.engineService.Call("system.ping", struct{}{}, &result)
	return result, err
}

// @PostRoute("/version")
// @Public
func (controller *SystemController) PostVersion() (SystemVersion, error) {
	var result SystemVersion
	err := controller.engineService.Call(controller.versionOperation(), struct{}{}, &result)
	return result, err
}

// @PostRoute("/build")
// @Allow(Administrator)
func (controller *SystemController) PostBuild(request *http.Request) (SystemBuild, error) {
	var result SystemBuild
	err := controller.tenantCallService.CallAsAdministrator(request, EngineCall{
		Operation:  controller.versionOperation(),
		Parameters: struct{}{},
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/readiness")
// @Public
func (controller *SystemController) PostReadiness() (SystemReadiness, error) {
	var result SystemReadiness
	err := controller.engineService.Call("system.readiness", struct{}{}, &result)
	return result, err
}

// @PostRoute("/metrics")
// @Allow(Administrator)
func (controller *SystemController) PostMetrics(request *http.Request) (SystemMetrics, error) {
	var result SystemMetrics
	err := controller.tenantCallService.CallAsAdministrator(request, EngineCall{
		Operation:  "system.metrics",
		Parameters: struct{}{},
		Result:     &result,
	})
	return result, err
}

func (controller *SystemController) versionOperation() string {
	return "system.version"
}
