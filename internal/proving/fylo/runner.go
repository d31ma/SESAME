// Package fylo contains the disposable FYLO viability experiment.
//
// It is deliberately separate from SESAME's application layer. Passing this
// experiment is evidence for an architectural gate, not a production storage
// implementation.
package fylo

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	fyloadapter "github.com/d31ma/sesame/internal/adapters/fylo"
)

const viabilityCollection = "sesame-viability-records"

// Report is the machine-readable result of one isolated FYLO viability run.
type Report struct {
	Passed                bool            `json:"passed"`
	Binary                string          `json:"binary"`
	BinarySHA256          string          `json:"binarySha256"`
	RuntimeVersion        string          `json:"runtimeVersion"`
	ProtocolVersion       int             `json:"protocolVersion"`
	Commit                string          `json:"commit"`
	BuildTarget           string          `json:"buildTarget"`
	BuildKind             string          `json:"buildKind"`
	MaxRequestBytes       int             `json:"maxRequestBytes"`
	MaxResponseBytes      int             `json:"maxResponseBytes"`
	ExclusiveRootEnforced bool            `json:"exclusiveRootEnforced"`
	Collection            string          `json:"collection"`
	DocumentID            string          `json:"documentId"`
	InitialReadMatched    bool            `json:"initialReadMatched"`
	RebuildSucceeded      bool            `json:"rebuildSucceeded"`
	RestartReadMatched    bool            `json:"restartReadMatched"`
	DurationMS            int64           `json:"durationMs"`
	CandidateLimitations  []string        `json:"candidateLimitations,omitempty"`
	PhaseOne              *PhaseOneReport `json:"phaseOne,omitempty"`
}

// Options configures an isolated FYLO candidate run.
type Options struct {
	Binary                 string
	ExpectedRuntimeVersion string
	ExpectedBuildTarget    string
	AllowDevelopmentBuild  bool
	FullPhaseOne           bool
}

// Run creates an ephemeral FYLO root, exercises persistence and rebuild, then
// removes the root. It never accepts a caller-owned data root.
func Run(ctx context.Context, options Options) (report Report, runErr error) {
	started := time.Now()
	report.Collection = viabilityCollection
	if options.Binary == "" {
		options.Binary = "fylo"
	}
	if options.ExpectedRuntimeVersion == "" {
		options.ExpectedRuntimeVersion = fyloadapter.PhaseOneRuntimeVersion
	}
	defer func() {
		report.DurationMS = time.Since(started).Milliseconds()
	}()

	resolvedBinary, err := exec.LookPath(options.Binary)
	if err != nil {
		return report, fmt.Errorf("locate FYLO binary %q: %w", options.Binary, err)
	}
	resolvedBinary, err = filepath.Abs(resolvedBinary)
	if err != nil {
		return report, fmt.Errorf("resolve FYLO binary path: %w", err)
	}
	report.Binary = resolvedBinary
	digest, err := binaryDigest(resolvedBinary)
	if err != nil {
		return report, err
	}
	report.BinarySHA256 = digest

	root, err := os.MkdirTemp("", "sesame-fylo-viability-*")
	if err != nil {
		return report, fmt.Errorf("create ephemeral FYLO root: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		_ = os.RemoveAll(root)
		return report, fmt.Errorf("restrict ephemeral FYLO root: %w", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(root); removeErr != nil && runErr == nil {
			runErr = fmt.Errorf("remove ephemeral FYLO root: %w", removeErr)
			report.Passed = false
		}
	}()

	marker, err := randomMarker()
	if err != nil {
		return report, fmt.Errorf("create viability marker: %w", err)
	}

	config := fyloadapter.Config{
		Binary:                 resolvedBinary,
		Root:                   root,
		ExpectedProtocol:       fyloadapter.ProtocolVersion,
		ExpectedRuntimeVersion: options.ExpectedRuntimeVersion,
		ExpectedBuildTarget:    options.ExpectedBuildTarget,
		AllowDevelopmentBuild:  options.AllowDevelopmentBuild,
	}
	client, err := fyloadapter.Start(ctx, config)
	if err != nil {
		return report, fmt.Errorf("start FYLO proving process: %w", err)
	}
	identity := client.Identity()
	report.RuntimeVersion = identity.RuntimeVersion
	report.ProtocolVersion = identity.ProtocolVersion
	report.Commit = identity.Commit
	report.BuildTarget = identity.BuildTarget
	report.BuildKind = identity.BuildKind
	report.MaxRequestBytes = identity.Machine.MaxRequestBytes
	report.MaxResponseBytes = identity.Machine.MaxResponseBytes
	if strings.HasPrefix(identity.BuildKind, "development") ||
		identity.Commit == "" ||
		identity.Commit == "unknown" {
		report.CandidateLimitations = append(
			report.CandidateLimitations,
			"development build explicitly allowed; immutable release commit is not proven",
		)
	}

	competitor, competitorErr := fyloadapter.Start(ctx, config)
	if competitor != nil {
		_ = competitor.Close()
		return report, closeAfterError(
			client,
			errors.New("FYLO allowed a competing exclusive owner for the same root"),
		)
	}
	var operationError *fyloadapter.OperationError
	if !errors.As(competitorErr, &operationError) || operationError.Code != "EROOTLOCKED" {
		return report, closeAfterError(
			client,
			fmt.Errorf("competing FYLO owner returned %T %v, want EROOTLOCKED", competitorErr, competitorErr),
		)
	}
	report.ExclusiveRootEnforced = true

	if err := request(ctx, client, "createCollection", map[string]any{
		"collection": viabilityCollection,
		"kind":       "document",
	}, nil); err != nil {
		return report, closeAfterError(client, err)
	}

	var documentID string
	if err := client.Request(ctx, "putData", map[string]any{
		"collection": viabilityCollection,
		"data": map[string]any{
			"kind":   "sesame-fylo-viability",
			"marker": marker,
		},
	}, &documentID); err != nil {
		return report, closeAfterError(client, fmt.Errorf("write viability record: %w", err))
	}
	if documentID == "" {
		return report, closeAfterError(client, errors.New("FYLO returned an empty document ID"))
	}
	report.DocumentID = documentID

	matched, err := readMarker(ctx, client, documentID, marker)
	if err != nil {
		return report, closeAfterError(client, err)
	}
	report.InitialReadMatched = matched
	if !matched {
		return report, closeAfterError(client, errors.New("FYLO initial read did not match written data"))
	}

	if err := request(ctx, client, "rebuildCollection", map[string]any{
		"collection": viabilityCollection,
	}, nil); err != nil {
		return report, closeAfterError(client, err)
	}
	report.RebuildSucceeded = true

	if err := client.Close(); err != nil {
		return report, fmt.Errorf("close initial FYLO proving process: %w", err)
	}

	restarted, err := fyloadapter.Start(ctx, config)
	if err != nil {
		return report, fmt.Errorf("restart FYLO proving process: %w", err)
	}
	matched, err = readMarker(ctx, restarted, documentID, marker)
	if err != nil {
		return report, closeAfterError(restarted, err)
	}
	report.RestartReadMatched = matched
	if !matched {
		return report, closeAfterError(restarted, errors.New("FYLO restart read did not match written data"))
	}
	if err := restarted.Close(); err != nil {
		return report, fmt.Errorf("close restarted FYLO proving process: %w", err)
	}

	if options.FullPhaseOne {
		phaseOne, err := runCompletePhaseOne(ctx, resolvedBinary, options)
		if err != nil {
			return report, fmt.Errorf("run complete Phase 1 suite: %w", err)
		}
		report.PhaseOne = &phaseOne
	}

	report.Passed = true
	return report, nil
}

func binaryDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open FYLO binary for hashing: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash FYLO binary: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func request(
	ctx context.Context,
	client *fyloadapter.Client,
	operation string,
	fields map[string]any,
	result any,
) error {
	var discarded json.RawMessage
	if result == nil {
		result = &discarded
	}
	if err := client.Request(ctx, operation, fields, result); err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return nil
}

func readMarker(
	ctx context.Context,
	client *fyloadapter.Client,
	documentID string,
	expected string,
) (bool, error) {
	var result map[string]json.RawMessage
	if err := client.Request(ctx, "getLatest", map[string]any{
		"collection": viabilityCollection,
		"id":         documentID,
	}, &result); err != nil {
		return false, fmt.Errorf("read viability record: %w", err)
	}
	document, exists := result[documentID]
	if !exists {
		return false, nil
	}
	var record struct {
		Kind   string `json:"kind"`
		Marker string `json:"marker"`
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return false, fmt.Errorf("decode viability record: %w", err)
	}
	return record.Kind == "sesame-fylo-viability" && record.Marker == expected, nil
}

func randomMarker() (string, error) {
	var marker [16]byte
	if _, err := rand.Read(marker[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(marker[:]), nil
}

func closeAfterError(client *fyloadapter.Client, cause error) error {
	if closeErr := client.Close(); closeErr != nil {
		return errors.Join(cause, closeErr)
	}
	return cause
}
