package contract_test

const (
	coverageRouted                = "routed"
	coverageStandardEndpoint      = "standard_endpoint"
	coverageCommandLineOnly       = "command_line_only"
	coverageNotRoutedForSecurity  = "not_routed_for_security"
	coverageCategoriesDescription = "routed, standard_endpoint, command_line_only, not_routed_for_security"
)

type operationCoverage struct {
	Category string   `json:"category"`
	Endpoint string   `json:"endpoint"`
	Routes   []string `json:"routes"`
	Reason   string   `json:"reason"`
}

func (coverage operationCoverage) hasKnownCategory() bool {
	switch coverage.Category {
	case coverageRouted, coverageStandardEndpoint, coverageCommandLineOnly, coverageNotRoutedForSecurity:
		return true
	}
	return false
}

func (coverage operationCoverage) mayBeRouted() bool {
	return coverage.Category == coverageRouted || coverage.Category == coverageStandardEndpoint
}

func (coverage operationCoverage) lists(route string) bool {
	for _, listed := range coverage.Routes {
		if listed == route {
			return true
		}
	}
	return false
}
