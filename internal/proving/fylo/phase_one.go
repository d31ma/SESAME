package fylo

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fyloadapter "github.com/d31ma/sesame/internal/adapters/fylo"
)

const (
	phaseOneEventCollection    = "sesame-phase-one-events"
	phaseOneSnapshotCollection = "sesame-phase-one-snapshots"
	phaseOneAttempts           = 1000
	phaseOneQueueCapacity      = 64
	// phaseOneEventPageLimit is deliberately smaller than the event count so
	// every replay exercises a multi-page cursor traversal.
	phaseOneEventPageLimit = 16
	phaseOneMaxEventPages  = 4096
)

var errAlreadyApplied = errors.New("security transition was already applied")

// PhaseOneReport contains evidence for the complete disposable Phase 1 suite.
type PhaseOneReport struct {
	Passed      bool                `json:"passed"`
	Concurrency PhaseOneConcurrency `json:"concurrency"`
	Ledger      PhaseOneLedger      `json:"ledger"`
	Pagination  PhaseOnePagination  `json:"pagination"`
	Recovery    PhaseOneRecovery    `json:"recovery"`
	Load        PhaseOneLoad        `json:"load"`
	Limitations []string            `json:"limitations"`
}

// PhaseOneConcurrency records exactly-once race outcomes.
type PhaseOneConcurrency struct {
	Attempts                    int `json:"attempts"`
	IdentifierWinners           int `json:"identifierWinners"`
	IdentifierRejections        int `json:"identifierRejections"`
	AuthorizationCodeWinners    int `json:"authorizationCodeWinners"`
	AuthorizationCodeRejections int `json:"authorizationCodeRejections"`
	RefreshTokenWinners         int `json:"refreshTokenWinners"`
	RefreshTokenRejections      int `json:"refreshTokenRejections"`
}

// PhaseOneLedger records append, replay, snapshot, and migration evidence.
type PhaseOneLedger struct {
	EventsAppended           int    `json:"eventsAppended"`
	HashChainVerified        bool   `json:"hashChainVerified"`
	SnapshotVerified         bool   `json:"snapshotVerified"`
	TamperedSnapshotRejected bool   `json:"tamperedSnapshotRejected"`
	RevocationEnforced       bool   `json:"revocationEnforced"`
	ReplayEquivalent         bool   `json:"replayEquivalent"`
	MigrationEquivalent      bool   `json:"migrationEquivalent"`
	DecisionEquivalent       bool   `json:"decisionEquivalent"`
	UpcastEvents             int    `json:"upcastEvents"`
	FinalProjectionSHA256    string `json:"finalProjectionSha256"`
}

// PhaseOnePagination records bounded cursor-paged event-ledger retrieval
// evidence.
type PhaseOnePagination struct {
	PageLimit             int  `json:"pageLimit"`
	PagesTraversed        int  `json:"pagesTraversed"`
	ItemsRetrieved        int  `json:"itemsRetrieved"`
	PagedEqualsUnpaged    bool `json:"pagedEqualsUnpaged"`
	InvalidCursorRejected bool `json:"invalidCursorRejected"`
}

// PhaseOneRecovery records crash, rebuild, corruption, and restore evidence.
type PhaseOneRecovery struct {
	CrashBeforeAppend               bool `json:"crashBeforeAppend"`
	CrashAfterAppend                bool `json:"crashAfterAppend"`
	CrashAfterSnapshot              bool `json:"crashAfterSnapshot"`
	LeaseRecoveredAfterCrash        bool `json:"leaseRecoveredAfterCrash"`
	IndexLossRebuilt                bool `json:"indexLossRebuilt"`
	BackupRestoreEquivalent         bool `json:"backupRestoreEquivalent"`
	AuthoritativeCorruptionDetected bool `json:"authoritativeCorruptionDetected"`
}

// PhaseOneLoad records bounded-queue, cancellation, leak, and latency evidence.
type PhaseOneLoad struct {
	QueueCapacity        int     `json:"queueCapacity"`
	QueueAccepted        int     `json:"queueAccepted"`
	QueueSaturated       int     `json:"queueSaturated"`
	CancellationEnforced bool    `json:"cancellationEnforced"`
	ChildRestarted       bool    `json:"childRestarted"`
	OperationsMeasured   int     `json:"operationsMeasured"`
	LatencyP50MS         float64 `json:"latencyP50Ms"`
	LatencyP95MS         float64 `json:"latencyP95Ms"`
	LatencyP99MS         float64 `json:"latencyP99Ms"`
	GoroutineDelta       int     `json:"goroutineDelta"`
	HeapAllocDeltaBytes  int64   `json:"heapAllocDeltaBytes"`
}

type securityEvent struct {
	Kind          string `json:"kind"`
	SchemaVersion int    `json:"schemaVersion"`
	Sequence      int    `json:"sequence"`
	Type          string `json:"type"`
	KeyHash       string `json:"keyHash"`
	PreviousHash  string `json:"previousHash"`
	Hash          string `json:"hash"`
}

type projection struct {
	Identifiers        map[string]bool `json:"identifiers"`
	AuthorizationCodes map[string]bool `json:"authorizationCodes"`
	RefreshTokens      map[string]bool `json:"refreshTokens"`
	Revocations        map[string]bool `json:"revocations"`
}

type verifiedSnapshot struct {
	Kind          string     `json:"kind"`
	SchemaVersion int        `json:"schemaVersion"`
	LastSequence  int        `json:"lastSequence"`
	LastEventHash string     `json:"lastEventHash"`
	State         projection `json:"state"`
	MAC           string     `json:"mac"`
}

type eventLedger struct {
	client    *fyloadapter.Client
	mu        sync.Mutex
	state     projection
	sequence  int
	lastHash  string
	eventIDs  []string
	latencies []time.Duration
}

func runCompletePhaseOne(
	ctx context.Context,
	binary string,
	options Options,
) (report PhaseOneReport, runErr error) {
	report.Limitations = []string{
		"FYLO internal transaction-phase SIGKILL coverage remains FYLO-native release evidence; this suite terminates at every SESAME acknowledgement boundary",
		"cold filesystem-copy restore is exercised locally; built-in S3 backup/restore requires separately provisioned object storage",
		"native support still requires this suite on each release OS/architecture and filesystem",
	}

	root, err := osMkdirPrivateTemp("sesame-phase-one-root-*")
	if err != nil {
		return report, err
	}
	defer func() {
		if removeErr := removePrivateTree(root); removeErr != nil && runErr == nil {
			runErr = removeErr
			report.Passed = false
		}
	}()

	config := fyloadapter.Config{
		Binary:                 binary,
		Root:                   root,
		ExpectedProtocol:       fyloadapter.ProtocolVersion,
		ExpectedRuntimeVersion: options.ExpectedRuntimeVersion,
		ExpectedBuildTarget:    options.ExpectedBuildTarget,
		AllowDevelopmentBuild:  options.AllowDevelopmentBuild,
	}
	client, err := fyloadapter.Start(ctx, config)
	if err != nil {
		return report, fmt.Errorf("start Phase 1 FYLO process: %w", err)
	}

	startGoroutines := runtime.NumGoroutine()
	var startMemory runtime.MemStats
	runtime.ReadMemStats(&startMemory)

	for _, collection := range []string{phaseOneEventCollection, phaseOneSnapshotCollection} {
		if err := request(ctx, client, "createCollection", map[string]any{
			"collection": collection,
			"kind":       "document",
		}, nil); err != nil {
			return report, closeAfterError(client, err)
		}
	}

	ledger := newEventLedger(client)
	identifier := "operator@example.invalid"
	code := randomHex(32)
	refresh := randomHex(32)
	if code == "" || refresh == "" {
		return report, closeAfterError(client, errors.New("generate Phase 1 single-use values"))
	}

	identifierRace := runConcurrentAttempts(ctx, phaseOneAttempts, func(ctx context.Context) error {
		return ledger.applyOnce(ctx, "identifier.claimed", normalizeIdentifier(identifier))
	})
	codeRace := runConcurrentAttempts(ctx, phaseOneAttempts, func(ctx context.Context) error {
		return ledger.applyOnce(ctx, "authorization-code.redeemed", code)
	})
	refreshRace := runConcurrentAttempts(ctx, phaseOneAttempts, func(ctx context.Context) error {
		return ledger.applyOnce(ctx, "refresh-token.redeemed", refresh)
	})
	report.Concurrency = PhaseOneConcurrency{
		Attempts:                    phaseOneAttempts,
		IdentifierWinners:           identifierRace.winners,
		IdentifierRejections:        identifierRace.rejections,
		AuthorizationCodeWinners:    codeRace.winners,
		AuthorizationCodeRejections: codeRace.rejections,
		RefreshTokenWinners:         refreshRace.winners,
		RefreshTokenRejections:      refreshRace.rejections,
	}
	if err := validateRaceReport(report.Concurrency); err != nil {
		return report, closeAfterError(client, err)
	}
	revokedSubject := "phase-one-subject"
	if err := ledger.applyOnce(ctx, "subject.revoked", revokedSubject); err != nil {
		return report, closeAfterError(client, err)
	}
	report.Ledger.RevocationEnforced = ledger.state.Revocations[keyDigest(revokedSubject)]
	if !report.Ledger.RevocationEnforced {
		return report, closeAfterError(client, errors.New("revocation event did not change the security projection"))
	}

	initialProjectionDigest := projectionDigest(ledger.state)
	events, replayed, err := replayEvents(ctx, client)
	if err != nil {
		return report, closeAfterError(client, fmt.Errorf("initial replay: %w", err))
	}
	report.Ledger.HashChainVerified = true
	report.Ledger.ReplayEquivalent = projectionDigest(replayed) == initialProjectionDigest
	if !report.Ledger.ReplayEquivalent {
		return report, closeAfterError(client, errors.New("initial event replay changed the security projection"))
	}

	snapshotKey := make([]byte, 32)
	if _, err := rand.Read(snapshotKey); err != nil {
		return report, closeAfterError(client, fmt.Errorf("generate snapshot key: %w", err))
	}
	snapshotID, _, err := writeSnapshot(
		ctx,
		client,
		snapshotKey,
		ledger.sequence,
		ledger.lastHash,
		ledger.state,
	)
	if err != nil {
		return report, closeAfterError(client, err)
	}
	loadedSnapshot, err := readSnapshot(ctx, client, snapshotID)
	if err != nil {
		return report, closeAfterError(client, err)
	}
	report.Ledger.SnapshotVerified = verifySnapshot(loadedSnapshot, snapshotKey)
	tampered := loadedSnapshot
	tampered.MAC = strings.Repeat("0", len(tampered.MAC))
	report.Ledger.TamperedSnapshotRejected = !verifySnapshot(tampered, snapshotKey)
	if !report.Ledger.SnapshotVerified || !report.Ledger.TamperedSnapshotRejected {
		return report, closeAfterError(client, errors.New("snapshot verification invariant failed"))
	}

	// Boundary 1: termination before append must not create an event.
	beforeCrashCount := len(events)
	if err := client.Crash(); err != nil {
		return report, fmt.Errorf("crash before append: %w", err)
	}
	client, err = fyloadapter.Start(ctx, config)
	if err != nil {
		return report, fmt.Errorf("restart after pre-append crash: %w", err)
	}
	report.Recovery.LeaseRecoveredAfterCrash = true
	ledger, events, err = ledgerFromReplay(ctx, client)
	if err != nil {
		return report, closeAfterError(client, fmt.Errorf("replay after pre-append crash: %w", err))
	}
	report.Recovery.CrashBeforeAppend = len(events) == beforeCrashCount
	if !report.Recovery.CrashBeforeAppend {
		return report, closeAfterError(client, errors.New("pre-append crash created an event"))
	}

	// Boundary 2: FYLO success before SESAME acknowledgement must replay.
	afterAppendID, err := ledger.appendLocked(ctx, "crash.after-append", keyDigest("after-append"))
	if err != nil {
		return report, closeAfterError(client, err)
	}
	if err := client.Crash(); err != nil {
		return report, fmt.Errorf("crash after append: %w", err)
	}
	client, err = fyloadapter.Start(ctx, config)
	if err != nil {
		return report, fmt.Errorf("restart after append crash: %w", err)
	}
	ledger, _, err = ledgerFromReplay(ctx, client)
	if err != nil {
		return report, closeAfterError(client, fmt.Errorf("replay after append crash: %w", err))
	}
	report.Recovery.CrashAfterAppend = slices.Contains(ledger.eventIDs, afterAppendID)
	if !report.Recovery.CrashAfterAppend {
		return report, closeAfterError(client, errors.New("acknowledged FYLO append was lost after crash"))
	}

	// Boundary 3: a durable verified snapshot survives before caller acknowledgement.
	crashSnapshotID, _, err := writeSnapshot(
		ctx,
		client,
		snapshotKey,
		ledger.sequence,
		ledger.lastHash,
		ledger.state,
	)
	if err != nil {
		return report, closeAfterError(client, err)
	}
	if err := client.Crash(); err != nil {
		return report, fmt.Errorf("crash after snapshot: %w", err)
	}
	client, err = fyloadapter.Start(ctx, config)
	if err != nil {
		return report, fmt.Errorf("restart after snapshot crash: %w", err)
	}
	crashSnapshot, err := readSnapshot(ctx, client, crashSnapshotID)
	if err != nil {
		return report, closeAfterError(client, err)
	}
	report.Recovery.CrashAfterSnapshot = verifySnapshot(crashSnapshot, snapshotKey)
	report.Load.ChildRestarted = true
	if !report.Recovery.CrashAfterSnapshot {
		return report, closeAfterError(client, errors.New("snapshot was lost or invalid after crash"))
	}
	ledger, _, err = ledgerFromReplay(ctx, client)
	if err != nil {
		return report, closeAfterError(client, fmt.Errorf("replay after snapshot crash: %w", err))
	}

	queueReport, err := exerciseBoundedQueue(ctx, ledger)
	if err != nil {
		return report, closeAfterError(client, err)
	}
	report.Load.QueueCapacity = phaseOneQueueCapacity
	report.Load.QueueAccepted = queueReport.accepted
	report.Load.QueueSaturated = queueReport.saturated

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	var cancelledResult json.RawMessage
	cancelErr := client.Request(cancelled, "handshake", nil, &cancelledResult)
	report.Load.CancellationEnforced = errors.Is(cancelErr, context.Canceled)
	if !report.Load.CancellationEnforced {
		return report, closeAfterError(client, fmt.Errorf("cancelled request returned %v", cancelErr))
	}

	finalEvents, finalProjection, err := replayEvents(ctx, client)
	if err != nil {
		return report, closeAfterError(client, fmt.Errorf("replay after load: %w", err))
	}
	finalDigest := projectionDigest(finalProjection)
	report.Ledger.EventsAppended = len(finalEvents)
	report.Ledger.FinalProjectionSHA256 = finalDigest

	pagedDocuments, pagesTraversed, err := pagedEventDocuments(ctx, client)
	if err != nil {
		return report, closeAfterError(client, fmt.Errorf("paged event traversal: %w", err))
	}
	var unpagedDocuments map[string]json.RawMessage
	if err := client.Request(ctx, "findDocs", map[string]any{
		"collection": phaseOneEventCollection,
		"query":      eventQuery(),
	}, &unpagedDocuments); err != nil {
		return report, closeAfterError(client, fmt.Errorf("unpaged event comparison read: %w", err))
	}
	report.Pagination.PageLimit = phaseOneEventPageLimit
	report.Pagination.PagesTraversed = pagesTraversed
	report.Pagination.ItemsRetrieved = len(pagedDocuments)
	report.Pagination.PagedEqualsUnpaged = documentSetsEqual(pagedDocuments, unpagedDocuments)
	if pagesTraversed < 2 || !report.Pagination.PagedEqualsUnpaged {
		return report, closeAfterError(client, fmt.Errorf(
			"paged retrieval produced %d pages and equivalence=%t against the unpaged ledger",
			pagesTraversed,
			report.Pagination.PagedEqualsUnpaged,
		))
	}
	_, invalidCursorErr := client.FindDocsPage(
		ctx,
		phaseOneEventCollection,
		eventQuery(),
		phaseOneEventPageLimit,
		"sesame-synthetic-invalid-cursor",
	)
	report.Pagination.InvalidCursorRejected = fyloadapter.IsInvalidCursor(invalidCursorErr)
	if !report.Pagination.InvalidCursorRejected {
		return report, closeAfterError(client, fmt.Errorf(
			"synthetic invalid cursor returned %v, want typed EINVALIDCURSOR",
			invalidCursorErr,
		))
	}

	if err := client.Close(); err != nil {
		return report, err
	}
	for _, collection := range []string{phaseOneEventCollection, phaseOneSnapshotCollection} {
		if err := RemoveDerivedIndex(root, collection); err != nil {
			return report, err
		}
	}
	client, err = fyloadapter.Start(ctx, config)
	if err != nil {
		return report, fmt.Errorf("restart after index loss: %w", err)
	}
	for _, collection := range []string{phaseOneEventCollection, phaseOneSnapshotCollection} {
		if err := request(ctx, client, "rebuildCollection", map[string]any{
			"collection": collection,
		}, nil); err != nil {
			return report, closeAfterError(client, err)
		}
	}
	_, rebuiltProjection, err := replayEvents(ctx, client)
	if err != nil {
		return report, closeAfterError(client, fmt.Errorf("replay after index rebuild: %w", err))
	}
	report.Recovery.IndexLossRebuilt = projectionDigest(rebuiltProjection) == finalDigest
	if !report.Recovery.IndexLossRebuilt {
		return report, closeAfterError(client, errors.New("index rebuild changed the security projection"))
	}

	if err := client.Close(); err != nil {
		return report, err
	}
	backupRoot, err := osMkdirPrivateTemp("sesame-phase-one-backup-*")
	if err != nil {
		return report, err
	}
	defer removePrivateTree(backupRoot)
	if err := CopyTree(root, backupRoot); err != nil {
		return report, fmt.Errorf("create cold FYLO backup: %w", err)
	}
	backupConfig := config
	backupConfig.Root = backupRoot
	restored, err := fyloadapter.Start(ctx, backupConfig)
	if err != nil {
		return report, fmt.Errorf("start restored FYLO root: %w", err)
	}
	restoredEvents, restoredProjection, err := replayEvents(ctx, restored)
	if err != nil {
		return report, closeAfterError(restored, fmt.Errorf("replay after cold restore: %w", err))
	}
	report.Recovery.BackupRestoreEquivalent = projectionDigest(restoredProjection) == finalDigest
	if !report.Recovery.BackupRestoreEquivalent {
		return report, closeAfterError(restored, errors.New("backup restore changed the security projection"))
	}

	_, migratedProjection, upcastCount, err := replayEventsMigrated(restoredEvents)
	if err != nil {
		return report, closeAfterError(restored, err)
	}
	report.Ledger.UpcastEvents = upcastCount
	report.Ledger.MigrationEquivalent = projectionDigest(migratedProjection) == finalDigest
	if !report.Ledger.MigrationEquivalent {
		return report, closeAfterError(restored, errors.New("migration changed security decisions"))
	}
	report.Ledger.DecisionEquivalent = report.Ledger.ReplayEquivalent &&
		report.Recovery.IndexLossRebuilt &&
		report.Recovery.BackupRestoreEquivalent &&
		report.Ledger.MigrationEquivalent &&
		migratedProjection.Revocations[keyDigest(revokedSubject)]
	if !report.Ledger.DecisionEquivalent {
		return report, closeAfterError(restored, errors.New("rebuild, restore, or migration changed a security decision"))
	}
	if err := restored.Close(); err != nil {
		return report, err
	}

	corruptRoot, err := osMkdirPrivateTemp("sesame-phase-one-corrupt-*")
	if err != nil {
		return report, err
	}
	defer removePrivateTree(corruptRoot)
	if err := CopyTree(backupRoot, corruptRoot); err != nil {
		return report, fmt.Errorf("create corruption test root: %w", err)
	}
	if len(finalEvents) == 0 {
		return report, errors.New("no event available for corruption test")
	}
	if err := corruptDocument(corruptRoot, phaseOneEventCollection, finalEvents[0].ID); err != nil {
		return report, err
	}
	corruptConfig := config
	corruptConfig.Root = corruptRoot
	corruptClient, err := fyloadapter.Start(ctx, corruptConfig)
	if err == nil {
		_, _, replayErr := replayEvents(ctx, corruptClient)
		report.Recovery.AuthoritativeCorruptionDetected = replayErr != nil
		_ = corruptClient.Close()
	} else {
		report.Recovery.AuthoritativeCorruptionDetected = true
	}
	if !report.Recovery.AuthoritativeCorruptionDetected {
		return report, errors.New("authoritative event corruption was not detected")
	}

	latencies := ledger.latencySnapshot()
	report.Load.OperationsMeasured = len(latencies)
	report.Load.LatencyP50MS = percentileMilliseconds(latencies, 0.50)
	report.Load.LatencyP95MS = percentileMilliseconds(latencies, 0.95)
	report.Load.LatencyP99MS = percentileMilliseconds(latencies, 0.99)

	runtime.GC()
	var endMemory runtime.MemStats
	runtime.ReadMemStats(&endMemory)
	report.Load.GoroutineDelta = runtime.NumGoroutine() - startGoroutines
	report.Load.HeapAllocDeltaBytes = int64(endMemory.Alloc) - int64(startMemory.Alloc)
	if report.Load.GoroutineDelta > 4 {
		return report, fmt.Errorf("phase 1 goroutine delta is %d", report.Load.GoroutineDelta)
	}

	report.Passed = true
	return report, nil
}

type storedEvent struct {
	ID    string
	Event securityEvent
}

func newEventLedger(client *fyloadapter.Client) *eventLedger {
	return &eventLedger{client: client, state: emptyProjection()}
}

func ledgerFromReplay(
	ctx context.Context,
	client *fyloadapter.Client,
) (*eventLedger, []storedEvent, error) {
	events, state, err := replayEvents(ctx, client)
	if err != nil {
		return nil, nil, err
	}
	ledger := &eventLedger{
		client:   client,
		state:    state,
		eventIDs: make([]string, 0, len(events)),
	}
	if len(events) > 0 {
		ledger.sequence = events[len(events)-1].Event.Sequence
		ledger.lastHash = events[len(events)-1].Event.Hash
	}
	for _, event := range events {
		ledger.eventIDs = append(ledger.eventIDs, event.ID)
	}
	return ledger, events, nil
}

func (l *eventLedger) applyOnce(ctx context.Context, eventType, key string) error {
	started := time.Now()
	defer func() {
		l.mu.Lock()
		l.latencies = append(l.latencies, time.Since(started))
		l.mu.Unlock()
	}()

	keyHash := keyDigest(key)
	l.mu.Lock()
	defer l.mu.Unlock()
	if projectionContains(l.state, eventType, keyHash) {
		return errAlreadyApplied
	}
	_, err := l.appendLocked(ctx, eventType, keyHash)
	return err
}

func (l *eventLedger) appendLocked(
	ctx context.Context,
	eventType string,
	keyHash string,
) (string, error) {
	event := securityEvent{
		Kind:          "security-event",
		SchemaVersion: 1,
		Sequence:      l.sequence + 1,
		Type:          eventType,
		KeyHash:       keyHash,
		PreviousHash:  l.lastHash,
	}
	event.Hash = eventDigest(event)

	var documentID string
	if err := l.client.Request(ctx, "putData", map[string]any{
		"collection": phaseOneEventCollection,
		"data":       event,
	}, &documentID); err != nil {
		return "", fmt.Errorf("append %s event: %w", eventType, err)
	}
	var written map[string]json.RawMessage
	if err := l.client.Request(ctx, "getLatest", map[string]any{
		"collection": phaseOneEventCollection,
		"id":         documentID,
	}, &written); err != nil {
		return "", fmt.Errorf("verify %s event: %w", eventType, err)
	}
	var verified securityEvent
	if err := json.Unmarshal(written[documentID], &verified); err != nil {
		return "", fmt.Errorf("decode appended event: %w", err)
	}
	if verified.Hash != event.Hash {
		return "", errors.New("FYLO read-after-write event hash mismatch")
	}
	if err := applyEvent(&l.state, event); err != nil {
		return "", err
	}
	l.sequence = event.Sequence
	l.lastHash = event.Hash
	l.eventIDs = append(l.eventIDs, documentID)
	return documentID, nil
}

func (l *eventLedger) latencySnapshot() []time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.latencies)
}

type raceResult struct {
	winners    int
	rejections int
}

func runConcurrentAttempts(
	ctx context.Context,
	attempts int,
	operation func(context.Context) error,
) raceResult {
	var winners atomic.Int64
	var rejections atomic.Int64
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(attempts)
	for range attempts {
		go func() {
			defer wait.Done()
			<-start
			err := operation(ctx)
			switch {
			case err == nil:
				winners.Add(1)
			case errors.Is(err, errAlreadyApplied):
				rejections.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	return raceResult{winners: int(winners.Load()), rejections: int(rejections.Load())}
}

func validateRaceReport(report PhaseOneConcurrency) error {
	for name, values := range map[string][2]int{
		"identifier":         {report.IdentifierWinners, report.IdentifierRejections},
		"authorization code": {report.AuthorizationCodeWinners, report.AuthorizationCodeRejections},
		"refresh token":      {report.RefreshTokenWinners, report.RefreshTokenRejections},
	} {
		if values[0] != 1 || values[1] != phaseOneAttempts-1 {
			return fmt.Errorf(
				"%s race produced %d winners and %d rejections",
				name,
				values[0],
				values[1],
			)
		}
	}
	return nil
}

func replayEvents(
	ctx context.Context,
	client *fyloadapter.Client,
) ([]storedEvent, projection, error) {
	documents, _, err := pagedEventDocuments(ctx, client)
	if err != nil {
		return nil, projection{}, fmt.Errorf("load security events: %w", err)
	}

	events := make([]storedEvent, 0, len(documents))
	for id, document := range documents {
		var event securityEvent
		decoder := json.NewDecoder(bytes.NewReader(document))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil {
			return nil, projection{}, fmt.Errorf("decode security event %s: %w", id, err)
		}
		events = append(events, storedEvent{ID: id, Event: event})
	}
	sort.Slice(events, func(left, right int) bool {
		return events[left].Event.Sequence < events[right].Event.Sequence
	})

	state := emptyProjection()
	previousHash := ""
	for index, stored := range events {
		event := stored.Event
		if event.Sequence != index+1 {
			return nil, projection{}, fmt.Errorf(
				"event sequence %d found at replay position %d",
				event.Sequence,
				index+1,
			)
		}
		if event.PreviousHash != previousHash || event.Hash != eventDigest(event) {
			return nil, projection{}, fmt.Errorf("event hash chain failed at sequence %d", event.Sequence)
		}
		if err := applyEvent(&state, event); err != nil {
			return nil, projection{}, err
		}
		previousHash = event.Hash
	}
	return events, state, nil
}

func eventQuery() map[string]any {
	return map[string]any{
		"$ops": []any{
			map[string]any{"kind": map[string]any{"$eq": "security-event"}},
		},
	}
}

func pagedEventDocuments(
	ctx context.Context,
	client *fyloadapter.Client,
) (map[string]json.RawMessage, int, error) {
	return client.FindDocsAll(
		ctx,
		phaseOneEventCollection,
		eventQuery(),
		phaseOneEventPageLimit,
		phaseOneMaxEventPages,
	)
}

func documentSetsEqual(left, right map[string]json.RawMessage) bool {
	if len(left) != len(right) {
		return false
	}
	for id, leftDocument := range left {
		rightDocument, exists := right[id]
		if !exists || !jsonEquivalent(leftDocument, rightDocument) {
			return false
		}
	}
	return true
}

func jsonEquivalent(left, right json.RawMessage) bool {
	var leftValue, rightValue any
	if json.Unmarshal(left, &leftValue) != nil || json.Unmarshal(right, &rightValue) != nil {
		return false
	}
	return reflect.DeepEqual(leftValue, rightValue)
}

func replayEventsMigrated(events []storedEvent) ([]storedEvent, projection, int, error) {
	migrated := make([]storedEvent, 0, len(events))
	state := emptyProjection()
	upcastCount := 0
	for _, stored := range events {
		event := stored.Event
		if event.SchemaVersion == 1 {
			event.SchemaVersion = 2
			upcastCount++
		}
		if event.SchemaVersion != 2 {
			return nil, projection{}, upcastCount, fmt.Errorf(
				"unsupported event schema %d",
				event.SchemaVersion,
			)
		}
		if err := applyEvent(&state, event); err != nil {
			return nil, projection{}, upcastCount, err
		}
		migrated = append(migrated, storedEvent{ID: stored.ID, Event: event})
	}
	return migrated, state, upcastCount, nil
}

func applyEvent(state *projection, event securityEvent) error {
	switch event.Type {
	case "identifier.claimed", "load.identifier.claimed":
		if state.Identifiers[event.KeyHash] {
			return errAlreadyApplied
		}
		state.Identifiers[event.KeyHash] = true
	case "authorization-code.redeemed", "load.authorization-code.redeemed":
		if state.AuthorizationCodes[event.KeyHash] {
			return errAlreadyApplied
		}
		state.AuthorizationCodes[event.KeyHash] = true
	case "refresh-token.redeemed", "load.refresh-token.redeemed":
		if state.RefreshTokens[event.KeyHash] {
			return errAlreadyApplied
		}
		state.RefreshTokens[event.KeyHash] = true
	case "subject.revoked":
		if state.Revocations[event.KeyHash] {
			return errAlreadyApplied
		}
		state.Revocations[event.KeyHash] = true
	case "crash.after-append":
	default:
		return fmt.Errorf("unknown security event type %q", event.Type)
	}
	return nil
}

func projectionContains(state projection, eventType, keyHash string) bool {
	switch eventType {
	case "identifier.claimed", "load.identifier.claimed":
		return state.Identifiers[keyHash]
	case "authorization-code.redeemed", "load.authorization-code.redeemed":
		return state.AuthorizationCodes[keyHash]
	case "refresh-token.redeemed", "load.refresh-token.redeemed":
		return state.RefreshTokens[keyHash]
	case "subject.revoked":
		return state.Revocations[keyHash]
	default:
		return false
	}
}

func emptyProjection() projection {
	return projection{
		Identifiers:        make(map[string]bool),
		AuthorizationCodes: make(map[string]bool),
		RefreshTokens:      make(map[string]bool),
		Revocations:        make(map[string]bool),
	}
}

func writeSnapshot(
	ctx context.Context,
	client *fyloadapter.Client,
	key []byte,
	sequence int,
	lastHash string,
	state projection,
) (string, verifiedSnapshot, error) {
	snapshot := verifiedSnapshot{
		Kind:          "verified-snapshot",
		SchemaVersion: 1,
		LastSequence:  sequence,
		LastEventHash: lastHash,
		State:         state,
	}
	snapshot.MAC = snapshotMAC(snapshot, key)
	var id string
	if err := client.Request(ctx, "putData", map[string]any{
		"collection": phaseOneSnapshotCollection,
		"data":       snapshot,
	}, &id); err != nil {
		return "", verifiedSnapshot{}, fmt.Errorf("write verified snapshot: %w", err)
	}
	return id, snapshot, nil
}

func readSnapshot(
	ctx context.Context,
	client *fyloadapter.Client,
	id string,
) (verifiedSnapshot, error) {
	var documents map[string]json.RawMessage
	if err := client.Request(ctx, "getLatest", map[string]any{
		"collection": phaseOneSnapshotCollection,
		"id":         id,
	}, &documents); err != nil {
		return verifiedSnapshot{}, fmt.Errorf("read verified snapshot: %w", err)
	}
	var snapshot verifiedSnapshot
	if err := json.Unmarshal(documents[id], &snapshot); err != nil {
		return verifiedSnapshot{}, fmt.Errorf("decode verified snapshot: %w", err)
	}
	return snapshot, nil
}

func verifySnapshot(snapshot verifiedSnapshot, key []byte) bool {
	decoded, err := hex.DecodeString(snapshot.MAC)
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(snapshotMAC(snapshot, key))
	if err != nil {
		return false
	}
	return hmac.Equal(decoded, expected)
}

func snapshotMAC(snapshot verifiedSnapshot, key []byte) string {
	snapshot.MAC = ""
	encoded, _ := json.Marshal(snapshot)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil))
}

func eventDigest(event securityEvent) string {
	event.Hash = ""
	encoded, _ := json.Marshal(event)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func projectionDigest(state projection) string {
	encoded, _ := json.Marshal(state)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func keyDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func normalizeIdentifier(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func randomHex(bytesCount int) string {
	value := make([]byte, bytesCount)
	if _, err := rand.Read(value); err != nil {
		return ""
	}
	return hex.EncodeToString(value)
}

type queueExercise struct {
	accepted  int
	saturated int
}

func exerciseBoundedQueue(ctx context.Context, ledger *eventLedger) (queueExercise, error) {
	type queuedTransition struct {
		eventType string
		key       string
	}
	queue := make(chan queuedTransition, phaseOneQueueCapacity)
	var accepted atomic.Int64
	var saturated atomic.Int64
	var wait sync.WaitGroup
	wait.Add(phaseOneAttempts)
	start := make(chan struct{})
	for index := range phaseOneAttempts {
		go func(index int) {
			defer wait.Done()
			<-start
			eventTypes := [...]string{
				"load.identifier.claimed",
				"load.authorization-code.redeemed",
				"load.refresh-token.redeemed",
			}
			select {
			case queue <- queuedTransition{
				eventType: eventTypes[index%len(eventTypes)],
				key:       fmt.Sprintf("load-%04d", index),
			}:
				accepted.Add(1)
			default:
				saturated.Add(1)
			}
		}(index)
	}
	close(start)
	wait.Wait()
	close(queue)

	for transition := range queue {
		if err := ledger.applyOnce(ctx, transition.eventType, transition.key); err != nil {
			return queueExercise{}, err
		}
	}
	result := queueExercise{
		accepted:  int(accepted.Load()),
		saturated: int(saturated.Load()),
	}
	if result.accepted != phaseOneQueueCapacity ||
		result.saturated != phaseOneAttempts-phaseOneQueueCapacity {
		return result, fmt.Errorf(
			"bounded queue accepted %d and saturated %d",
			result.accepted,
			result.saturated,
		)
	}
	return result, nil
}

func percentileMilliseconds(values []time.Duration, percentile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := slices.Clone(values)
	sort.Slice(sorted, func(left, right int) bool { return sorted[left] < sorted[right] })
	index := int(float64(len(sorted)-1) * percentile)
	return float64(sorted[index].Microseconds()) / 1000
}
