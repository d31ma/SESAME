import (
	"encoding/json"

	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Service
type StandardsRefusalService struct{}

func (service *StandardsRefusalService) Refusal(status int, code string) sesame.StandardsResponse {
	body, _ := json.Marshal(StandardsProblem{Error: code})
	return sesame.StandardsResponse{
		ContractVersion: service.contractVersion(),
		Status:          status,
		Headers: map[string]string{
			"cache-control":          "no-store",
			"pragma":                 "no-cache",
			"content-type":           "application/json",
			"x-content-type-options": "nosniff",
		},
		Body: body,
	}
}

func (service *StandardsRefusalService) contractVersion() string {
	return "1"
}
