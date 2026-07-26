// Command fylo-viability runs the disposable Phase 1 FYLO proving experiment.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	fyloadapter "github.com/d31ma/sesame/internal/adapters/fylo"
	fyloproving "github.com/d31ma/sesame/internal/proving/fylo"
)

func main() {
	os.Exit(run())
}

func run() int {
	flags := flag.NewFlagSet("fylo-viability", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	binary := flags.String("binary", "fylo", "path or executable name for the FYLO runtime")
	expectedRuntimeVersion := flags.String(
		"expected-runtime-version",
		fyloadapter.PhaseOneRuntimeVersion,
		"required FYLO runtime version",
	)
	expectedBuildTarget := flags.String(
		"expected-build-target",
		"",
		"required FYLO build target; defaults to the SESAME process target",
	)
	allowDevelopmentBuild := flags.Bool(
		"allow-development-build",
		false,
		"allow a FYLO candidate without immutable release build identity",
	)
	profile := flags.String("profile", "lifecycle", "experiment profile: lifecycle or full")
	timeout := flags.Duration("timeout", 5*time.Minute, "maximum duration for the experiment")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(os.Stderr, "fylo-viability: unexpected positional arguments")
		return 2
	}
	if *profile != "lifecycle" && *profile != "full" {
		_, _ = fmt.Fprintf(os.Stderr, "fylo-viability: unsupported profile %q\n", *profile)
		return 2
	}

	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(signalContext, *timeout)
	defer cancel()

	report, err := fyloproving.Run(ctx, fyloproving.Options{
		Binary:                 *binary,
		ExpectedRuntimeVersion: *expectedRuntimeVersion,
		ExpectedBuildTarget:    *expectedBuildTarget,
		AllowDevelopmentBuild:  *allowDevelopmentBuild,
		FullPhaseOne:           *profile == "full",
	})
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "fylo-viability: %v\n", err)
		return 1
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "fylo-viability: encode report: %v\n", err)
		return 1
	}
	return 0
}
