// Package securityledger persists SESAME's authoritative security events as
// FYLO documents. No other production module speaks the FYLO protocol.
package securityledger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	fyloadapter "github.com/d31ma/sesame/internal/adapters/fylo"
	"github.com/d31ma/sesame/internal/domain/audit"
)

const (
	// Collection is the FYLO collection holding the security-event ledger.
	Collection = "sesame-security-events"

	// replayPageLimit bounds one replay page well below the negotiated
	// response frame.
	replayPageLimit = 256
	// replayMaxPages is a defensive cap, not a capacity claim.
	replayMaxPages = 1 << 20
)

// Ledger appends hash-chained security events for one exclusively owned FYLO
// root. The initial topology has exactly one writer; the internal mutex
// serializes appends within that single process.
type Ledger struct {
	client *fyloadapter.Client
	key    []byte

	mu           sync.Mutex
	lastSequence int64
	lastHash     string
}

// Replay reports how the current state was reconstructed at open time.
type Replay struct {
	// SnapshotState is the verified projection checkpoint, nil when the open
	// performed a complete replay.
	SnapshotState    json.RawMessage
	SnapshotSequence int64
	SnapshotsStored  int
	// TailEvents are the verified events after the snapshot position; with a
	// nil SnapshotState they are the complete ledger.
	TailEvents []audit.Event
}

// Open prepares the ledger collection, replays the complete chain through
// bounded pages, verifies it, and returns the ordered events for projection
// building. A verification failure fails closed.
func Open(ctx context.Context, client *fyloadapter.Client) (*Ledger, []audit.Event, error) {
	ledger, replayed, err := OpenVerified(ctx, client, nil)
	if err != nil {
		return nil, nil, err
	}
	return ledger, replayed.TailEvents, nil
}

// OpenVerified opens the ledger with an optional snapshot MAC key. With a
// key, the newest verified snapshot bounds replay to the events after its
// position and any stored snapshot that fails verification is a fail-closed
// error. Without a key, snapshots are ignored and the complete ledger is
// replayed; the ledger stays authoritative either way.
func OpenVerified(
	ctx context.Context,
	client *fyloadapter.Client,
	snapshotKey []byte,
) (*Ledger, Replay, error) {
	for _, collection := range []string{Collection, SnapshotCollection} {
		var created map[string]any
		if err := client.Request(ctx, "createCollection", map[string]any{
			"collection": collection,
			"kind":       "document",
		}, &created); err != nil {
			return nil, Replay{}, fmt.Errorf("prepare collection %s: %w", collection, err)
		}
	}

	replayed := Replay{}
	fromSequence := int64(0)
	fromHash := ""
	if len(snapshotKey) != 0 {
		snapshot, stored, err := latestVerifiedSnapshot(ctx, client, snapshotKey)
		if err != nil {
			return nil, Replay{}, err
		}
		replayed.SnapshotsStored = stored
		if snapshot != nil {
			replayed.SnapshotState = json.RawMessage(snapshot.State)
			replayed.SnapshotSequence = snapshot.LastSequence
			fromSequence = snapshot.LastSequence
			fromHash = snapshot.LastEventHash
		}
	}

	events, err := replay(ctx, client, fromSequence, fromHash)
	if err != nil {
		return nil, Replay{}, err
	}
	replayed.TailEvents = events

	ledger := &Ledger{
		client:       client,
		key:          snapshotKey,
		lastSequence: fromSequence,
		lastHash:     fromHash,
	}
	if len(events) > 0 {
		ledger.lastSequence = events[len(events)-1].Sequence
		ledger.lastHash = events[len(events)-1].Hash
	}
	return ledger, replayed, nil
}

// Append durably records one security event and returns it after FYLO
// acknowledges the write.
func (l *Ledger) Append(
	ctx context.Context,
	eventType string,
	tenantID string,
	actor string,
	payload any,
) (audit.Event, error) {
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		return audit.Event{}, fmt.Errorf("encode %s payload: %w", eventType, err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	event := audit.Event{
		Kind:          audit.EventKind,
		SchemaVersion: audit.SchemaVersion,
		Sequence:      l.lastSequence + 1,
		Type:          eventType,
		TenantID:      tenantID,
		Actor:         actor,
		OccurredAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Payload:       encodedPayload,
		PreviousHash:  l.lastHash,
	}
	event.Hash = event.Digest()
	if err := event.Validate(); err != nil {
		return audit.Event{}, fmt.Errorf("refuse invalid %s event: %w", eventType, err)
	}

	var documentID string
	if err := l.client.Request(ctx, "putData", map[string]any{
		"collection": Collection,
		"data":       event,
	}, &documentID); err != nil {
		return audit.Event{}, fmt.Errorf("append %s event: %w", eventType, err)
	}
	if documentID == "" {
		return audit.Event{}, fmt.Errorf("append %s event: FYLO returned an empty document ID", eventType)
	}

	l.lastSequence = event.Sequence
	l.lastHash = event.Hash
	return event, nil
}

func replay(
	ctx context.Context,
	client *fyloadapter.Client,
	fromSequence int64,
	fromHash string,
) ([]audit.Event, error) {
	clause := map[string]any{"kind": map[string]any{"$eq": audit.EventKind}}
	if fromSequence > 0 {
		// One $ops clause is a conjunction; separate clauses would be OR'd.
		clause["sequence"] = map[string]any{"$gt": fromSequence}
	}
	documents, _, err := client.FindDocsAll(ctx, Collection, map[string]any{
		"$ops": []any{clause},
	}, replayPageLimit, replayMaxPages)
	if err != nil {
		return nil, fmt.Errorf("replay security ledger: %w", err)
	}

	events := make([]audit.Event, 0, len(documents))
	for id, document := range documents {
		var event audit.Event
		decoder := json.NewDecoder(bytes.NewReader(document))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil {
			return nil, fmt.Errorf("decode security event %s: %w", id, err)
		}
		events = append(events, event)
	}
	sort.Slice(events, func(left, right int) bool {
		return events[left].Sequence < events[right].Sequence
	})
	// The hash chain covers the stored form, so it is verified before any
	// schema upcast reinterprets an event.
	if err := audit.VerifyChainFrom(events, fromSequence, fromHash); err != nil {
		return nil, fmt.Errorf("security ledger verification failed: %w", err)
	}
	for index, event := range events {
		upcast, err := audit.Upcast(event)
		if err != nil {
			return nil, fmt.Errorf("security ledger replay: %w", err)
		}
		events[index] = upcast
	}
	return events, nil
}
