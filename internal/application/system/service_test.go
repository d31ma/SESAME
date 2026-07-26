package system

import (
	"context"
	"testing"

	"github.com/d31ma/sesame/internal/platform/buildinfo"
)

func TestServiceReportsLivenessAndFailsReadinessClosed(t *testing.T) {
	t.Parallel()

	service := New(buildinfo.New("dev", "unknown", "unknown"))

	if got := service.Liveness(); got != (Status{Status: StatusOK}) {
		t.Fatalf("Liveness() = %#v", got)
	}

	got := service.Readiness(context.Background())
	want := Status{Status: StatusNotReady, ReasonCode: ReasonStorageNotConfigured}
	if got != want {
		t.Fatalf("Readiness() = %#v, want %#v", got, want)
	}
}
