// Package system provides transport-independent process status use cases.
package system

import (
	"context"

	"github.com/d31ma/sesame/internal/platform/buildinfo"
)

const (
	// StatusOK means the queried process function is healthy.
	StatusOK = "ok"
	// StatusNotReady means the process is alive but cannot safely execute
	// security operations.
	StatusNotReady = "not_ready"

	// ReasonStorageNotConfigured prevents the scaffold from claiming readiness
	// before the authoritative FYLO runtime is connected and verified.
	ReasonStorageNotConfigured = "storage_not_configured"
)

// Status is the stable public representation of process health.
type Status struct {
	Status     string `json:"status"`
	ReasonCode string `json:"reason_code,omitempty"`
}

// Service answers process-level queries without depending on a transport.
type Service struct {
	info         buildinfo.Info
	storageReady bool
}

// New constructs the process-level application service.
func New(info buildinfo.Info) *Service {
	return &Service{info: info}
}

// MarkStorageReady records that the authoritative FYLO boundary is connected,
// verified, and replayed. It is called once during startup wiring, before the
// service answers requests.
func (s *Service) MarkStorageReady() {
	s.storageReady = true
}

// Info returns immutable metadata for the running binary.
func (s *Service) Info() buildinfo.Info {
	return s.info
}

// Liveness reports whether the process can answer requests.
func (s *Service) Liveness() Status {
	return Status{Status: StatusOK}
}

// Readiness fails closed until the FYLO persistence boundary is configured.
func (s *Service) Readiness(context.Context) Status {
	if !s.storageReady {
		return Status{
			Status:     StatusNotReady,
			ReasonCode: ReasonStorageNotConfigured,
		}
	}
	return Status{Status: StatusOK}
}
