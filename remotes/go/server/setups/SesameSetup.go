// @Setup
type SesameSetup struct{}

func (SesameSetup) Configure(execution *BehaviorExecution) (*BehaviorConfiguration, error) {
	configuration := NewBehaviorConfiguration()
	configuration.Http["sesame"] = &SesameTransportHelper{}
	return configuration, nil
}
