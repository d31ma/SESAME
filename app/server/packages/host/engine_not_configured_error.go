package host

// EngineNotConfiguredError reports unusable sesame settings in the Yon
// application snapshot. The host refuses to start an engine from them.
type EngineNotConfiguredError struct{}

func (failure *EngineNotConfiguredError) Error() string {
	return "sesame.binary and sesame.deployment must be absolute paths, " +
		"and sesame.waitmilliseconds must stay within the range in docs/YON.md"
}

// ErrorCode returns engine_not_configured.
func (failure *EngineNotConfiguredError) ErrorCode() string {
	return "engine_not_configured"
}
