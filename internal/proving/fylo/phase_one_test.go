package fylo

import (
	"errors"
	"testing"
	"time"
)

func TestEventChainAndMigrationPreserveProjection(t *testing.T) {
	t.Parallel()

	state := emptyProjection()
	events := make([]storedEvent, 0, 3)
	previousHash := ""
	for index, eventType := range []string{
		"identifier.claimed",
		"authorization-code.redeemed",
		"refresh-token.redeemed",
		"subject.revoked",
	} {
		event := securityEvent{
			Kind:          "security-event",
			SchemaVersion: 1,
			Sequence:      index + 1,
			Type:          eventType,
			KeyHash:       keyDigest(eventType),
			PreviousHash:  previousHash,
		}
		event.Hash = eventDigest(event)
		if err := applyEvent(&state, event); err != nil {
			t.Fatalf("applyEvent() error = %v", err)
		}
		events = append(events, storedEvent{ID: eventType, Event: event})
		previousHash = event.Hash
	}

	migrated, migratedState, upcastCount, err := replayEventsMigrated(events)
	if err != nil {
		t.Fatalf("replayEventsMigrated() error = %v", err)
	}
	if upcastCount != len(events) {
		t.Fatalf("upcast count = %d, want %d", upcastCount, len(events))
	}
	if projectionDigest(migratedState) != projectionDigest(state) {
		t.Fatal("migration changed the security projection")
	}
	for _, stored := range migrated {
		if stored.Event.SchemaVersion != 2 {
			t.Fatalf("migrated schema version = %d, want 2", stored.Event.SchemaVersion)
		}
	}

	tampered := events[1].Event
	tampered.KeyHash = keyDigest("tampered")
	if tampered.Hash == eventDigest(tampered) {
		t.Fatal("event digest accepted tampered content")
	}
}

func TestSnapshotMACRejectsTampering(t *testing.T) {
	t.Parallel()

	key := []byte("0123456789abcdef0123456789abcdef")
	snapshot := verifiedSnapshot{
		Kind:          "verified-snapshot",
		SchemaVersion: 1,
		LastSequence:  4,
		LastEventHash: keyDigest("event"),
		State:         emptyProjection(),
	}
	snapshot.State.Identifiers[keyDigest("operator@example.invalid")] = true
	snapshot.MAC = snapshotMAC(snapshot, key)
	if !verifySnapshot(snapshot, key) {
		t.Fatal("verifySnapshot() rejected valid snapshot")
	}

	snapshot.LastSequence++
	if verifySnapshot(snapshot, key) {
		t.Fatal("verifySnapshot() accepted tampered snapshot")
	}
}

func TestApplyEventRejectsDuplicateAndUnknownTransitions(t *testing.T) {
	t.Parallel()

	state := emptyProjection()
	event := securityEvent{Type: "identifier.claimed", KeyHash: keyDigest("operator@example.invalid")}
	if err := applyEvent(&state, event); err != nil {
		t.Fatalf("first applyEvent() error = %v", err)
	}
	if err := applyEvent(&state, event); !errors.Is(err, errAlreadyApplied) {
		t.Fatalf("duplicate applyEvent() error = %v, want errAlreadyApplied", err)
	}
	if err := applyEvent(&state, securityEvent{Type: "unknown"}); err == nil {
		t.Fatal("applyEvent() accepted unknown event type")
	}
}

func TestPercentileMilliseconds(t *testing.T) {
	t.Parallel()

	values := []time.Duration{
		10 * time.Millisecond,
		40 * time.Millisecond,
		20 * time.Millisecond,
		30 * time.Millisecond,
	}
	if got := percentileMilliseconds(values, 0.50); got != 20 {
		t.Fatalf("p50 = %v, want 20", got)
	}
	if got := percentileMilliseconds(values, 0.99); got != 30 {
		t.Fatalf("p99 = %v, want 30", got)
	}
	if got := percentileMilliseconds(nil, 0.95); got != 0 {
		t.Fatalf("empty percentile = %v, want 0", got)
	}
}
