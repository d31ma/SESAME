package securityledger

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	fyloadapter "github.com/d31ma/sesame/internal/adapters/fylo"
)

const (
	// SnapshotCollection holds HMAC-verified projection snapshots. Snapshots
	// are rebuildable accelerators; the event ledger stays authoritative.
	SnapshotCollection = "sesame-security-snapshots"

	snapshotKind          = "security-snapshot"
	snapshotSchemaVersion = 1
)

// Snapshot is one verified projection checkpoint. State is an opaque JSON
// string: it is authenticated by the MAC and never queried by field, which
// also keeps the document inside FYLO's data model — embedded arrays of
// objects are deliberately rejected there and belong in their own
// collections.
type Snapshot struct {
	Kind          string `json:"kind"`
	SchemaVersion int    `json:"schema_version"`
	LastSequence  int64  `json:"last_sequence"`
	LastEventHash string `json:"last_event_hash"`
	State         string `json:"state"`
	MAC           string `json:"mac"`
}

func (s Snapshot) mac(key []byte) (string, error) {
	unsigned := s
	unsigned.MAC = ""
	encoded, err := json.Marshal(unsigned)
	if err != nil {
		return "", fmt.Errorf("encode snapshot for verification: %w", err)
	}
	authenticator := hmac.New(sha256.New, key)
	authenticator.Write(encoded)
	return hex.EncodeToString(authenticator.Sum(nil)), nil
}

func (s Snapshot) verify(key []byte) error {
	expected, err := s.mac(key)
	if err != nil {
		return err
	}
	if s.Kind != snapshotKind || s.SchemaVersion != snapshotSchemaVersion {
		return fmt.Errorf("snapshot has unsupported kind %q version %d", s.Kind, s.SchemaVersion)
	}
	if s.MAC == "" || !hmac.Equal([]byte(expected), []byte(s.MAC)) {
		return errors.New("snapshot failed MAC verification")
	}
	return nil
}

// WriteSnapshot durably records a verified checkpoint of the caller's
// projection state at the ledger's current position. It fails when the
// ledger was opened without a snapshot key.
func (l *Ledger) WriteSnapshot(ctx context.Context, state any) error {
	if len(l.key) == 0 {
		return errors.New("security ledger has no snapshot key configured")
	}
	encodedState, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode snapshot state: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	snapshot := Snapshot{
		Kind:          snapshotKind,
		SchemaVersion: snapshotSchemaVersion,
		LastSequence:  l.lastSequence,
		LastEventHash: l.lastHash,
		State:         string(encodedState),
	}
	snapshot.MAC, err = snapshot.mac(l.key)
	if err != nil {
		return err
	}

	var documentID string
	if err := l.client.Request(ctx, "putData", map[string]any{
		"collection": SnapshotCollection,
		"data":       snapshot,
	}, &documentID); err != nil {
		return fmt.Errorf("write snapshot: %w", err)
	}
	if documentID == "" {
		return errors.New("write snapshot: FYLO returned an empty document ID")
	}
	return nil
}

// latestVerifiedSnapshot loads every stored snapshot and returns the one at
// the highest sequence. Any stored snapshot that fails verification is a
// fail-closed error, not a silent fallback: a tampered accelerator means the
// deployment needs attention even though the ledger itself is authoritative.
func latestVerifiedSnapshot(
	ctx context.Context,
	client *fyloadapter.Client,
	key []byte,
) (*Snapshot, int, error) {
	documents, _, err := client.FindDocsAll(ctx, SnapshotCollection, map[string]any{
		"$ops": []any{
			map[string]any{"kind": map[string]any{"$eq": snapshotKind}},
		},
	}, replayPageLimit, replayMaxPages)
	if err != nil {
		return nil, 0, fmt.Errorf("load snapshots: %w", err)
	}

	snapshots := make([]Snapshot, 0, len(documents))
	for id, document := range documents {
		var snapshot Snapshot
		decoder := json.NewDecoder(bytes.NewReader(document))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&snapshot); err != nil {
			return nil, 0, fmt.Errorf("decode snapshot %s: %w", id, err)
		}
		if err := snapshot.verify(key); err != nil {
			return nil, 0, fmt.Errorf("snapshot %s: %w", id, err)
		}
		snapshots = append(snapshots, snapshot)
	}
	if len(snapshots) == 0 {
		return nil, 0, nil
	}
	sort.Slice(snapshots, func(left, right int) bool {
		return snapshots[left].LastSequence < snapshots[right].LastSequence
	})
	latest := snapshots[len(snapshots)-1]
	return &latest, len(snapshots), nil
}
