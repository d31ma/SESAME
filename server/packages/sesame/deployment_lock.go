package sesame

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// deploymentLockedCode is the FYLO error code an engine reports when another
// live process owns the deployment's FYLO root.
const deploymentLockedCode = "EROOTLOCKED"

// deploymentRetryInterval is the pause between start attempts while another
// engine owns the deployment.
const deploymentRetryInterval = 50 * time.Millisecond

// ErrDeploymentLocked reports that the engine could not start because another
// live engine owns the deployment. Nothing ran, so starting again is safe.
var ErrDeploymentLocked = errors.New("another sesame engine owns the deployment")

// StartWhenAvailable starts an engine like Start. While another engine owns
// the deployment it tries again until ctx ends. When ctx ends first, the
// error always wraps ctx.Err(), whether the deadline fell between attempts or
// during an attempt; it also wraps ErrDeploymentLocked when the last attempt
// found the deployment locked. Any other failure returns at once.
func StartWhenAvailable(ctx context.Context, options Options) (*Client, error) {
	for {
		client, err := Start(ctx, options)
		if !errors.Is(err, ErrDeploymentLocked) {
			return client, err
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %w", err, ctx.Err())
		case <-time.After(deploymentRetryInterval):
		}
	}
}
