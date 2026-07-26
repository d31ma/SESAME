package fylo_test

import (
	"context"
	"os"
	"testing"
	"time"

	fyloadapter "github.com/d31ma/sesame/internal/adapters/fylo"
	fyloproving "github.com/d31ma/sesame/internal/proving/fylo"
)

func TestRealFYLOViability(t *testing.T) {
	if os.Getenv("SESAME_FYLO_INTEGRATION") != "1" {
		t.Skip("set SESAME_FYLO_INTEGRATION=1 to test a real FYLO runtime")
	}

	binary := os.Getenv("FYLO_BINARY")
	if binary == "" {
		binary = "fylo"
	}
	fullPhaseOne := os.Getenv("SESAME_FYLO_PROFILE") == "full"
	timeout := 30 * time.Second
	if fullPhaseOne {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	report, err := fyloproving.Run(ctx, fyloproving.Options{
		Binary:                 binary,
		ExpectedRuntimeVersion: fyloadapter.PhaseOneRuntimeVersion,
		ExpectedBuildTarget:    os.Getenv("SESAME_FYLO_BUILD_TARGET"),
		AllowDevelopmentBuild:  os.Getenv("SESAME_FYLO_ALLOW_DEVELOPMENT") == "1",
		FullPhaseOne:           fullPhaseOne,
	})
	if err != nil {
		t.Fatalf("FYLO viability run failed: %v", err)
	}
	if !report.Passed ||
		!report.InitialReadMatched ||
		!report.ExclusiveRootEnforced ||
		!report.RebuildSucceeded ||
		!report.RestartReadMatched {
		t.Fatalf("incomplete FYLO viability report: %#v", report)
	}
	if fullPhaseOne && (report.PhaseOne == nil || !report.PhaseOne.Passed) {
		t.Fatalf("incomplete Phase 1 report: %#v", report.PhaseOne)
	}
}
