import (
	"encoding/json"

	"github.com/d31ma/sesame/app/server/packages/sesame"
)

type StandardsContractUtils struct{}

func (StandardsContractUtils) Version() string {
	return "1"
}

func (StandardsContractUtils) Refusal(status int, code string) sesame.StandardsResponse {
	body, _ := json.Marshal(StandardsProblem{Error: code})
	return sesame.StandardsResponse{
		ContractVersion: StandardsContractUtils{}.Version(),
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
