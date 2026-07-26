package audit

import (
	"encoding/json"
	"testing"
)

func chain(t *testing.T, count int) []Event {
	t.Helper()

	events := make([]Event, 0, count)
	previousHash := ""
	for index := range count {
		event := Event{
			Kind:          EventKind,
			SchemaVersion: SchemaVersion,
			Sequence:      int64(index) + 1,
			Type:          "tenant.bootstrapped",
			TenantID:      "tnt_00000000000000000000000000000000",
			Actor:         "test",
			OccurredAt:    "2026-07-24T00:00:00Z",
			Payload:       json.RawMessage(`{"n":1}`),
			PreviousHash:  previousHash,
		}
		event.Hash = event.Digest()
		events = append(events, event)
		previousHash = event.Hash
	}
	return events
}

func TestVerifyChainAcceptsValidChain(t *testing.T) {
	t.Parallel()

	if err := VerifyChain(nil); err != nil {
		t.Fatalf("VerifyChain(empty) error = %v", err)
	}
	if err := VerifyChain(chain(t, 5)); err != nil {
		t.Fatalf("VerifyChain(valid) error = %v", err)
	}
}

func TestVerifyChainFailsClosed(t *testing.T) {
	t.Parallel()

	tamperedPayload := chain(t, 3)
	tamperedPayload[1].Payload = json.RawMessage(`{"n":2}`)

	brokenLink := chain(t, 3)
	brokenLink[2].PreviousHash = "forged"

	gap := chain(t, 3)
	gap[2].Sequence = 4

	wrongKind := chain(t, 1)
	wrongKind[0].Kind = "note"

	for name, events := range map[string][]Event{
		"tampered payload": tamperedPayload,
		"broken link":      brokenLink,
		"sequence gap":     gap,
		"wrong kind":       wrongKind,
	} {
		if err := VerifyChain(events); err == nil {
			t.Fatalf("VerifyChain(%s) accepted a corrupt chain", name)
		}
	}
}

func TestUpcastFailsClosedOnUnknownVersionsAndTypes(t *testing.T) {
	t.Parallel()

	current := chain(t, 1)[0]
	upcast, err := Upcast(current)
	if err != nil || upcast.SchemaVersion != SchemaVersion {
		t.Fatalf("Upcast(current) = %#v, %v", upcast, err)
	}

	future := chain(t, 1)[0]
	future.SchemaVersion = SchemaVersion + 1
	if _, err := Upcast(future); err == nil {
		t.Fatal("Upcast() accepted a future schema version")
	}

	unknown := chain(t, 1)[0]
	unknown.Type = "federation.linked"
	if _, err := Upcast(unknown); err == nil {
		t.Fatal("Upcast() accepted an unregistered event type")
	}
}

func TestValidateRejectsIncompleteEvents(t *testing.T) {
	t.Parallel()

	valid := chain(t, 1)[0]
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate(valid) error = %v", err)
	}

	for name, mutate := range map[string]func(*Event){
		"kind":       func(e *Event) { e.Kind = "" },
		"schema":     func(e *Event) { e.SchemaVersion = 2 },
		"sequence":   func(e *Event) { e.Sequence = 0 },
		"type":       func(e *Event) { e.Type = "" },
		"actor":      func(e *Event) { e.Actor = "" },
		"occurredAt": func(e *Event) { e.OccurredAt = "" },
	} {
		event := chain(t, 1)[0]
		mutate(&event)
		if err := event.Validate(); err == nil {
			t.Fatalf("Validate() accepted an event with invalid %s", name)
		}
	}
}
