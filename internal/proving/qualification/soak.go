package qualification

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"time"

	sesame "github.com/d31ma/sesame/clients/go/sesame"
)

func runSoak(
	ctx context.Context,
	config Config,
	deployment string,
	seeded scenario,
) (SoakEvidence, error) {
	report := SoakEvidence{
		Status:                    StatusFailed,
		ConfiguredDurationSeconds: config.SoakDuration.Seconds(),
	}
	client, err := start(ctx, config.SESAMEBinary, deployment)
	if err != nil {
		return report, fmt.Errorf("start soak deployment: %w", err)
	}

	before, err := client.Metrics(ctx)
	if err != nil {
		_ = client.Close()
		return report, fmt.Errorf("read pre-soak metrics: %w", err)
	}
	report.HeapBytesBefore = before.HeapAllocBytes
	report.GoroutinesBefore = before.Goroutines
	report.DeploymentBytesBefore, err = deploymentSize(deployment)
	if err != nil {
		_ = client.Close()
		return report, err
	}

	started := time.Now()
	var latencies latencyHistogram
	var operationErrors []error
	for time.Since(started) < config.SoakDuration || report.Operations < config.MinOperations {
		if err := ctx.Err(); err != nil {
			_ = client.Close()
			return report, err
		}

		operationStarted := time.Now()
		var operationErr error
		if report.Operations%20 == 0 {
			identifier := sesame.PrincipalIdentifier{
				Namespace: "email",
				Value: fmt.Sprintf(
					"soak-%012d@qualification.invalid",
					report.Operations,
				),
			}
			_, operationErr = client.PrincipalCreate(
				ctx, seeded.TenantID, "workload", identifier)
			if operationErr == nil {
				report.WriteOperations++
			}
		} else {
			request := seeded.Request
			request.PrincipalID = seeded.AllowedPrincipal
			var decision sesame.Decision
			decision, operationErr = client.Decide(ctx, request, nil)
			if operationErr == nil && decision.Decision != "allow" {
				operationErr = fmt.Errorf(
					"soak authorization returned %q with reason %q",
					decision.Decision,
					decision.ReasonCode,
				)
			}
		}
		latencies.Observe(time.Since(operationStarted))
		report.Operations++
		if operationErr != nil {
			report.OperationErrors++
			if len(operationErrors) < 8 {
				operationErrors = append(operationErrors, operationErr)
			}
		}
	}
	report.DurationMilliseconds = milliseconds(time.Since(started))

	after, metricsErr := client.Metrics(ctx)
	closeErr := client.Close()
	if err := errors.Join(metricsErr, closeErr); err != nil {
		return report, fmt.Errorf("finish soak process: %w", err)
	}
	report.HeapBytesAfter = after.HeapAllocBytes
	report.HeapGrowthBytes = signedDelta(after.HeapAllocBytes, before.HeapAllocBytes)
	report.GoroutinesAfter = after.Goroutines
	report.GoroutineGrowth = after.Goroutines - before.Goroutines
	report.DeploymentBytesAfter, err = deploymentSize(deployment)
	if err != nil {
		return report, err
	}
	report.DeploymentGrowthBytes =
		report.DeploymentBytesAfter - report.DeploymentBytesBefore
	if report.Operations != 0 {
		report.OperationErrorRatio =
			float64(report.OperationErrors) / float64(report.Operations)
		report.OperationsPerSecond =
			float64(report.Operations) / (report.DurationMilliseconds / 1000)
	}
	report.LatencyHistogram = latencyHistogramMethod
	report.P50Milliseconds = milliseconds(latencies.Percentile(0.50))
	report.P95Milliseconds = milliseconds(latencies.Percentile(0.95))
	report.P99Milliseconds = milliseconds(latencies.Percentile(0.99))

	var violations []error
	if report.Operations < config.MinOperations {
		violations = append(violations, fmt.Errorf(
			"completed %d operations, below minimum %d",
			report.Operations, config.MinOperations))
	}
	if report.OperationErrorRatio > config.Limits.MaxOperationErrorRatio {
		violations = append(violations, fmt.Errorf(
			"operation error ratio %.6f exceeds %.6f",
			report.OperationErrorRatio,
			config.Limits.MaxOperationErrorRatio,
		))
	}
	if config.Limits.EnforceResources {
		violations = append(violations, resourceLimitViolations(report, config.Limits)...)
	}
	violations = append(violations, operationErrors...)
	if err := errors.Join(violations...); err != nil {
		return report, fmt.Errorf("soak limits failed: %w", err)
	}
	report.Status = StatusPassed
	return report, nil
}

func resourceLimitViolations(report SoakEvidence, limits Limits) []error {
	var violations []error
	if time.Duration(report.P99Milliseconds*float64(time.Millisecond)) > limits.MaxP99 {
		violations = append(violations, fmt.Errorf(
			"p99 %.3fms exceeds %.3fms",
			report.P99Milliseconds,
			milliseconds(limits.MaxP99),
		))
	}
	if report.HeapGrowthBytes > limits.MaxHeapGrowthBytes {
		violations = append(violations, fmt.Errorf(
			"heap growth %d exceeds %d bytes",
			report.HeapGrowthBytes,
			limits.MaxHeapGrowthBytes,
		))
	}
	if report.GoroutineGrowth > limits.MaxGoroutineGrowth {
		violations = append(violations, fmt.Errorf(
			"goroutine growth %d exceeds %d",
			report.GoroutineGrowth,
			limits.MaxGoroutineGrowth,
		))
	}
	if report.DeploymentGrowthBytes > limits.MaxDeploymentGrowth {
		violations = append(violations, fmt.Errorf(
			"deployment growth %d exceeds %d bytes",
			report.DeploymentGrowthBytes,
			limits.MaxDeploymentGrowth,
		))
	}
	return violations
}

func deploymentSize(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refuse symlink in evidence deployment: %s", path)
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("measure deployment size: %w", err)
	}
	return total, nil
}

func signedDelta(after, before uint64) int64 {
	if after >= before {
		delta := after - before
		if delta > math.MaxInt64 {
			return math.MaxInt64
		}
		return int64(delta)
	}
	delta := before - after
	if delta > math.MaxInt64 {
		return math.MinInt64
	}
	return -int64(delta)
}

const (
	latencyHistogramSubdivisions = 32
	latencyHistogramBuckets      = 64 * latencyHistogramSubdivisions
	latencyHistogramMethod       = "fixed-log2-32-upper-bound"
)

// latencyHistogram bounds qualification-run memory independently of duration.
// Each power-of-two nanosecond range has 32 logarithmic subdivisions and a
// percentile reports the selected bucket's upper bound.
type latencyHistogram struct {
	buckets [latencyHistogramBuckets]uint64
	total   uint64
}

func (h *latencyHistogram) Observe(duration time.Duration) {
	nanoseconds := duration.Nanoseconds()
	if nanoseconds < 1 {
		nanoseconds = 1
	}
	index := int(math.Floor(
		math.Log2(float64(nanoseconds)) * latencyHistogramSubdivisions,
	))
	if index < 0 {
		index = 0
	}
	if index >= len(h.buckets) {
		index = len(h.buckets) - 1
	}
	h.buckets[index]++
	h.total++
}

func (h *latencyHistogram) Percentile(quantile float64) time.Duration {
	if h.total == 0 {
		return 0
	}
	target := uint64(math.Ceil(quantile * float64(h.total)))
	if target == 0 {
		target = 1
	}
	var observed uint64
	for index, count := range h.buckets {
		observed += count
		if observed < target {
			continue
		}
		upperNanoseconds := math.Pow(
			2,
			float64(index+1)/latencyHistogramSubdivisions,
		)
		if upperNanoseconds >= float64(math.MaxInt64) {
			return time.Duration(math.MaxInt64)
		}
		return time.Duration(math.Ceil(upperNanoseconds))
	}
	return time.Duration(math.MaxInt64)
}
