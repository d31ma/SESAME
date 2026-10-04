type EngineNotConfiguredError struct{}

func (failure *EngineNotConfiguredError) Error() string {
	return "sesame.binary and sesame.deployment must be absolute paths, and sesame.waitmilliseconds must stay within the range in docs/YON.md"
}
