package sesame

import (
	"context"
	"errors"
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
// the deployment it tries again until ctx ends, and then returns an error
// that wraps ErrDeploymentLocked. Any other failure returns at once.
func StartWhenAvailable(ctx context.Context, options Options) (*Client, error) {
	var locked error
	for {
		client, err := Start(ctx, options)
		if !errors.Is(err, ErrDeploymentLocked) {
			return client, lockedWhenOutOfTime(ctx, err, locked)
		}
		locked = err
		select {
		case <-ctx.Done():
			return nil, locked
		case <-time.After(deploymentRetryInterval):
		}
	}
}

// lockedWhenOutOfTime keeps the lock as the reason when ctx ran out between
// a locked attempt and the next one, so callers see why they waited.
func lockedWhenOutOfTime(ctx context.Context, err, locked error) error {
	if err != nil && locked != nil && ctx.Err() != nil {
		return locked
	}
	return err
}
