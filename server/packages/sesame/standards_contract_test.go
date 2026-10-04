package sesame

import (
	"context"
	"testing"
)

func TestSDKContractScenarioStandardsDispatchUsesTheVersionedEngineContract(t *testing.T) {
	t.Parallel()

	client, err := Start(context.Background(), Options{Binary: testBinary})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	result, err := client.StandardsDispatch(context.Background(), StandardsRequest{
		ContractVersion: "unsupported",
		Endpoint:        "oidc.token",
		Method:          "GET",
	})
	if err != nil {
		t.Fatalf("StandardsDispatch() error = %v", err)
	}
	if result.ContractVersion != "1" || result.Status != 405 || result.Headers["allow"] != "POST" {
		t.Fatalf("StandardsDispatch() = %#v", result)
	}
	if string(result.Body) != `{"error":"invalid_request"}` {
		t.Fatalf("StandardsDispatch() body = %s", result.Body)
	}
}
