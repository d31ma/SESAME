type SystemVersion struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	Commit          string   `json:"commit"`
	BuiltAt         string   `json:"built_at"`
	GoVersion       string   `json:"go_version"`
	OS              string   `json:"os"`
	Arch            string   `json:"arch"`
	ProtocolVersion string   `json:"protocol_version"`
	Operations      []string `json:"operations"`
}
