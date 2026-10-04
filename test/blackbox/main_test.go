package blackbox_test

import (
	"os"
	"testing"
)

var engineEnvironmentVariables = []string{
	"SESAME_DEPLOYMENT",
	"FYLO_BINARY",
	"FYLO_ROOT",
	"SESAME_ISSUER",
	"SESAME_SESSION_SECRET",
	"SESAME_PROVIDER_CLIENT_SECRET",
}

func TestMain(m *testing.M) {
	for _, variable := range engineEnvironmentVariables {
		_ = os.Unsetenv(variable)
	}
	os.Exit(m.Run())
}
