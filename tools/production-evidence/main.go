// Command production-evidence runs destructive release drills exclusively in
// private temporary deployments and emits one JSON report.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/d31ma/sesame/internal/proving/qualification"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("production-evidence", flag.ContinueOnError)
	flags.SetOutput(stderr)
	profile := flags.String("profile", string(qualification.ProfileSmoke),
		"evidence profile: smoke or release")
	sesameBinary := flags.String("sesame-binary", "",
		"absolute path to the exact current SESAME executable")
	previousBinary := flags.String("previous-sesame-binary", "",
		"absolute path to the exact previous SESAME executable")
	fyloBinary := flags.String("fylo-binary", "",
		"absolute path to the exact FYLO executable")
	environmentLabel := flags.String("environment-label", "",
		"stable description of reference hardware, filesystem, and storage")
	soakDuration := flags.Duration("soak-duration", time.Minute,
		"duration of the mixed read/write workload")
	minimumOperations := flags.Int("min-operations", 1,
		"minimum operations the soak must complete")
	timeout := flags.Duration("timeout", 0,
		"whole-run deadline; default is soak duration plus ten minutes")
	enforceResources := flags.Bool("enforce-resource-limits", false,
		"fail when p99 or process/deployment growth exceeds configured limits")
	maxP99 := flags.Duration("max-p99", 0,
		"maximum admitted-operation p99 latency")
	maxHeapGrowth := flags.Int64("max-heap-growth-bytes", 0,
		"maximum SESAME child heap growth")
	maxGoroutineGrowth := flags.Int("max-goroutine-growth", 0,
		"maximum SESAME child goroutine growth")
	maxDeploymentGrowth := flags.Int64("max-deployment-growth-bytes", 0,
		"maximum deployment growth during the workload")
	maxErrorRatio := flags.Float64("max-operation-error-ratio", 0,
		"maximum failed-operation ratio from 0 through 1")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "production-evidence: unexpected positional arguments")
		return 2
	}

	config := qualification.Config{
		Profile:              qualification.Profile(*profile),
		SESAMEBinary:         *sesameBinary,
		PreviousSESAMEBinary: *previousBinary,
		FYLOBinary:           *fyloBinary,
		EnvironmentLabel:     *environmentLabel,
		SoakDuration:         *soakDuration,
		MinOperations:        *minimumOperations,
		Limits: qualification.Limits{
			EnforceResources:       *enforceResources,
			MaxP99:                 *maxP99,
			MaxHeapGrowthBytes:     *maxHeapGrowth,
			MaxGoroutineGrowth:     *maxGoroutineGrowth,
			MaxDeploymentGrowth:    *maxDeploymentGrowth,
			MaxOperationErrorRatio: *maxErrorRatio,
		},
	}
	if err := qualification.ValidateConfig(config); err != nil {
		_, _ = fmt.Fprintf(stderr, "production-evidence: %v\n", err)
		return 2
	}

	runTimeout := *timeout
	if runTimeout == 0 {
		runTimeout = config.SoakDuration + 10*time.Minute
	}
	runContext, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	report, runErr := qualification.Run(runContext, config)
	if err := json.NewEncoder(stdout).Encode(report); err != nil {
		_, _ = fmt.Fprintf(stderr, "production-evidence: encode report: %v\n", err)
		return 1
	}
	if runErr != nil {
		_, _ = fmt.Fprintf(stderr, "production-evidence: %v\n", runErr)
		return 1
	}
	return 0
}
