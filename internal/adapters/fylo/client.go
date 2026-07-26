// Package fylo provides the process boundary between SESAME and FYLO.
package fylo

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// ProtocolVersion is the FYLO machine protocol version supported by SESAME.
	ProtocolVersion = 1
	// PhaseOneRuntimeVersion is the FYLO candidate pinned for the Phase 1 gate.
	PhaseOneRuntimeVersion = "26.30.06"

	requiredCHEXVersion       = "26.28.02"
	requiredTTIDVersion       = "26.28.02"
	defaultMaxRequestBytes    = 1 << 20
	defaultMaxResponseBytes   = 8 << 20
	maxMachineFrameBytes      = 64 << 20
	defaultMaxDiagnosticBytes = 64 << 10
	defaultShutdownTimeout    = 5 * time.Second
)

var errClientClosed = errors.New("FYLO client is closed")

// Config defines the FYLO process and the limits enforced at its trust boundary.
type Config struct {
	Binary string
	Root   string
	// SchemaDir and EncryptionKey enable FYLO's at-rest field encryption.
	// Both must be set together. The key never enters a FYLO document: it
	// reaches the child through its environment only.
	//
	// Unused by SESAME today: FYLO decrypts only in a process that has
	// already written to the collection, so a read-only startup replay
	// receives ciphertext (FYLO issue #84). The wiring is kept because it
	// is correct and small, and adoption becomes a one-line change once
	// reads decrypt independently of write history.
	SchemaDir              string
	EncryptionKey          string
	CipherSalt             string
	ExpectedProtocol       int
	ExpectedRuntimeVersion string
	ExpectedBuildTarget    string
	AllowDevelopmentBuild  bool
	MaxRequestBytes        int
	MaxResponseBytes       int
	MaxDiagnosticBytes     int
	ShutdownTimeout        time.Duration
}

// CompatibilityError reports a FYLO machine protocol version mismatch.
type CompatibilityError struct {
	Expected int
	Actual   int
}

func (e *CompatibilityError) Error() string {
	return fmt.Sprintf("FYLO protocol version mismatch: expected %d, received %d", e.Expected, e.Actual)
}

// RuntimeCompatibilityError reports a FYLO runtime identity that SESAME cannot
// safely use for the configured compatibility contract.
type RuntimeCompatibilityError struct {
	Field    string
	Expected string
	Actual   string
}

func (e *RuntimeCompatibilityError) Error() string {
	return fmt.Sprintf(
		"FYLO runtime identity mismatch for %s: expected %q, received %q",
		e.Field,
		e.Expected,
		e.Actual,
	)
}

// OperationError reports a well-formed error returned by a FYLO operation.
type OperationError struct {
	Operation string
	Name      string
	Message   string
	Code      string
}

func (e *OperationError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("FYLO %s failed: %s: %s", e.Operation, e.Name, e.Message)
	}
	return fmt.Sprintf("FYLO %s failed [%s]: %s: %s", e.Operation, e.Code, e.Name, e.Message)
}

// Client owns one persistent FYLO subprocess. Requests are serialized because
// FYLO's stdio protocol is an ordered request-response stream.
type Client struct {
	config     Config
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	stdout     *bufio.Reader
	stdoutPipe io.Closer

	requestGate  chan struct{}
	stateMu      sync.Mutex
	closed       bool
	expectedExit bool
	waitDone     chan struct{}
	waitErr      error

	diagnostics *tailBuffer
	protocol    int
	identity    RuntimeIdentity
}

// RuntimeIdentity is the negotiated identity and framing contract returned by
// FYLO's side-effect-free handshake.
type RuntimeIdentity struct {
	RuntimeVersion  string              `json:"runtimeVersion"`
	ProtocolVersion int                 `json:"protocolVersion"`
	Commit          string              `json:"commit"`
	BuildTarget     string              `json:"buildTarget"`
	BuildKind       string              `json:"buildKind"`
	Dependencies    RuntimeDependencies `json:"dependencies"`
	Machine         MachineContract     `json:"machine"`
	Capabilities    RuntimeCapabilities `json:"capabilities"`
}

// RuntimeDependencies describes FYLO's required vendor executables.
type RuntimeDependencies struct {
	CHEX RuntimeDependency `json:"chex"`
	TTID RuntimeDependency `json:"ttid"`
}

// RuntimeDependency identifies one required vendor executable.
type RuntimeDependency struct {
	RequiredVersion string `json:"requiredVersion"`
	Available       bool   `json:"available"`
}

// MachineContract describes FYLO's effective stdio framing contract.
type MachineContract struct {
	Framing                    string `json:"framing"`
	Encoding                   string `json:"encoding"`
	Delimiter                  string `json:"delimiter"`
	DelimiterCountsTowardLimit bool   `json:"delimiterCountsTowardLimit"`
	MaxRequestBytes            int    `json:"maxRequestBytes"`
	MaxResponseBytes           int    `json:"maxResponseBytes"`
	DuplicateKeys              string `json:"duplicateKeys"`
	TruncatedFrame             string `json:"truncatedFrame"`
	MalformedFrame             string `json:"malformedFrame"`
}

// RuntimeCapabilities describes FYLO machine features required by SESAME.
type RuntimeCapabilities struct {
	Handshake       bool                       `json:"handshake"`
	ExclusiveRoot   bool                       `json:"exclusiveRoot"`
	QueryPagination *QueryPaginationCapability `json:"queryPagination"`
}

// QueryPaginationCapability describes FYLO's bounded cursor-pagination
// contract for collection queries.
type QueryPaginationCapability struct {
	Version       int      `json:"version"`
	Operations    []string `json:"operations"`
	DefaultItems  int      `json:"defaultItems"`
	MaxItems      int      `json:"maxItems"`
	Ordering      string   `json:"ordering"`
	RestartPolicy string   `json:"restartPolicy"`
}

// Start launches FYLO and validates its protocol before returning a usable client.
func Start(ctx context.Context, config Config) (*Client, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	command := exec.Command(
		normalized.Binary,
		"exec",
		"--loop",
		"--root",
		normalized.Root,
		"--exclusive-root",
		"--max-request-bytes",
		strconv.Itoa(normalized.MaxRequestBytes),
		"--max-response-bytes",
		strconv.Itoa(normalized.MaxResponseBytes),
	)
	if normalized.EncryptionKey != "" {
		// exec.Command inherits the parent environment by default; the
		// encryption material is appended rather than replacing it so the
		// child keeps its PATH and locale.
		command.Env = append(os.Environ(),
			"FYLO_SCHEMA="+normalized.SchemaDir,
			"FYLO_ENCRYPTION_KEY="+normalized.EncryptionKey,
			"FYLO_CIPHER_SALT="+normalized.CipherSalt,
		)
	}

	childStdin, stdin, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create FYLO stdin pipe: %w", err)
	}
	stdout, childStdout, err := os.Pipe()
	if err != nil {
		_ = childStdin.Close()
		_ = stdin.Close()
		return nil, fmt.Errorf("create FYLO stdout pipe: %w", err)
	}
	stderr, childStderr, err := os.Pipe()
	if err != nil {
		_ = childStdin.Close()
		_ = stdin.Close()
		_ = stdout.Close()
		_ = childStdout.Close()
		return nil, fmt.Errorf("create FYLO stderr pipe: %w", err)
	}
	command.Stdin = childStdin
	command.Stdout = childStdout
	command.Stderr = childStderr

	client := &Client{
		config:      normalized,
		cmd:         command,
		stdin:       stdin,
		stdout:      bufio.NewReaderSize(stdout, min(normalized.MaxResponseBytes+1, 64<<10)),
		stdoutPipe:  stdout,
		requestGate: make(chan struct{}, 1),
		waitDone:    make(chan struct{}),
		diagnostics: newTailBuffer(normalized.MaxDiagnosticBytes),
	}
	client.requestGate <- struct{}{}
	if err := command.Start(); err != nil {
		_ = childStdin.Close()
		_ = stdin.Close()
		_ = stdout.Close()
		_ = childStdout.Close()
		_ = stderr.Close()
		_ = childStderr.Close()
		return nil, fmt.Errorf("start FYLO: %w", err)
	}
	_ = childStdin.Close()
	_ = childStdout.Close()
	_ = childStderr.Close()

	go func() {
		defer stderr.Close()
		_, _ = io.Copy(client.diagnostics, stderr)
	}()
	go func() {
		err := command.Wait()
		client.stateMu.Lock()
		client.waitErr = err
		client.closed = true
		client.stateMu.Unlock()
		close(client.waitDone)
	}()

	var identityFrame json.RawMessage
	err = client.Request(ctx, "handshake", nil, &identityFrame)
	if err != nil {
		// A failed handshake usually means the child died or refused the
		// root. Its stderr is the only account of why, so it travels with
		// the error instead of being discarded with the process.
		return nil, fmt.Errorf("perform FYLO handshake: %w%s", err, client.diagnosticSuffix())
	}
	identity, err := decodeRuntimeIdentity(identityFrame)
	if err != nil {
		_ = client.terminate()
		return nil, fmt.Errorf("decode FYLO runtime identity: %w%s", err, client.diagnosticSuffix())
	}
	if err := validateRuntimeIdentity(identity, normalized); err != nil {
		_ = client.terminate()
		return nil, err
	}
	client.identity = identity

	return client, nil
}

// ProtocolVersion returns the protocol version validated during startup.
func (c *Client) ProtocolVersion() int {
	return c.protocol
}

// Identity returns the immutable runtime identity negotiated during startup.
func (c *Client) Identity() RuntimeIdentity {
	return c.identity
}

// Diagnostics returns the bounded tail of FYLO's stderr stream.
func (c *Client) Diagnostics() string {
	return c.diagnostics.String()
}

// Request performs one correlated FYLO machine-protocol operation.
func (c *Client) Request(
	ctx context.Context,
	operation string,
	fields map[string]any,
	result any,
) error {
	if operation == "" {
		return errors.New("FYLO operation is required")
	}
	if result == nil {
		return errors.New("FYLO result target is required")
	}
	for _, reserved := range []string{"op", "requestId", "root"} {
		if _, exists := fields[reserved]; exists {
			return fmt.Errorf("FYLO request field %q is owned by the adapter", reserved)
		}
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.requestGate:
	}
	defer func() { c.requestGate <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return err
	}

	if c.isClosed() {
		return c.closedError()
	}

	requestID, err := newRequestID()
	if err != nil {
		return fmt.Errorf("create FYLO request ID: %w", err)
	}
	request := make(map[string]any, len(fields)+2)
	for key, value := range fields {
		request[key] = value
	}
	request["op"] = operation
	request["requestId"] = requestID

	frame, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode FYLO %s request: %w", operation, err)
	}
	if len(frame) > c.config.MaxRequestBytes {
		return fmt.Errorf(
			"FYLO %s request is %d bytes; limit is %d",
			operation,
			len(frame),
			c.config.MaxRequestBytes,
		)
	}
	frame = append(frame, '\n')
	if _, err := c.stdin.Write(frame); err != nil {
		_ = c.terminate()
		return fmt.Errorf("write FYLO %s request: %w", operation, err)
	}

	type readResult struct {
		frame []byte
		err   error
	}
	read := make(chan readResult, 1)
	go func() {
		responseFrame, readErr := c.readFrame()
		read <- readResult{frame: responseFrame, err: readErr}
	}()

	var responseRead readResult
	select {
	case <-ctx.Done():
		_ = c.terminate()
		<-read
		return ctx.Err()
	case responseRead = <-read:
	}
	if responseRead.err != nil {
		_ = c.terminate()
		return fmt.Errorf("read FYLO %s response: %w", operation, responseRead.err)
	}

	response, err := decodeResponse(responseRead.frame)
	if err != nil {
		_ = c.terminate()
		return fmt.Errorf("decode FYLO %s response: %w", operation, err)
	}
	if response.ProtocolVersion != c.config.ExpectedProtocol {
		_ = c.terminate()
		return &CompatibilityError{
			Expected: c.config.ExpectedProtocol,
			Actual:   response.ProtocolVersion,
		}
	}
	if c.protocol == 0 {
		c.protocol = response.ProtocolVersion
	}
	if !response.OK && response.Operation == nil && response.RequestID == nil {
		if len(response.Result) != 0 || response.Failure == nil {
			_ = c.terminate()
			return errors.New("FYLO startup failure has an invalid result/error shape")
		}
		return &OperationError{
			Operation: "startup",
			Name:      response.Failure.Name,
			Message:   response.Failure.Message,
			Code:      response.Failure.Code,
		}
	}
	if response.Operation == nil {
		_ = c.terminate()
		return errors.New("FYLO response has no op")
	}
	if *response.Operation != operation {
		_ = c.terminate()
		return fmt.Errorf(
			"FYLO response operation mismatch: requested %q, received %q",
			operation,
			*response.Operation,
		)
	}
	if response.RequestID == nil {
		_ = c.terminate()
		return errors.New("FYLO response has no requestId")
	}
	if *response.RequestID != requestID {
		_ = c.terminate()
		return fmt.Errorf(
			"FYLO response request ID mismatch: expected %q, received %q",
			requestID,
			*response.RequestID,
		)
	}

	if !response.OK {
		if len(response.Result) != 0 || response.Failure == nil {
			_ = c.terminate()
			return errors.New("FYLO failure response has an invalid result/error shape")
		}
		return &OperationError{
			Operation: operation,
			Name:      response.Failure.Name,
			Message:   response.Failure.Message,
			Code:      response.Failure.Code,
		}
	}
	if len(response.Result) == 0 || response.Failure != nil {
		_ = c.terminate()
		return errors.New("FYLO success response has an invalid result/error shape")
	}
	if err := json.Unmarshal(response.Result, result); err != nil {
		_ = c.terminate()
		return fmt.Errorf("decode FYLO %s result: %w", operation, err)
	}
	return nil
}

// diagnosticSuffix terminates the child and returns its exit status and
// stderr tail for inclusion in a startup error. Both are bounded already:
// diagnostics use the configured tail buffer.
func (c *Client) diagnosticSuffix() string {
	waitErr := c.terminate()
	var details []string
	if waitErr != nil {
		details = append(details, "child exit: "+waitErr.Error())
	}
	if diagnostics := strings.TrimSpace(c.Diagnostics()); diagnostics != "" {
		details = append(details, "child stderr: "+diagnostics)
	}
	if len(details) == 0 {
		return ""
	}
	return " (" + strings.Join(details, "; ") + ")"
}

// Close stops and reaps the FYLO subprocess. It is safe to call more than once.
func (c *Client) Close() error {
	<-c.requestGate
	defer func() { c.requestGate <- struct{}{} }()

	c.stateMu.Lock()
	alreadyClosed := c.closed
	if !alreadyClosed {
		c.expectedExit = true
	}
	c.stateMu.Unlock()
	_ = c.stdin.Close()
	timer := time.NewTimer(c.config.ShutdownTimeout)
	select {
	case <-c.waitDone:
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	case <-timer.C:
		c.stateMu.Lock()
		c.expectedExit = true
		c.stateMu.Unlock()
		if c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
		}
		<-c.waitDone
	}

	c.stateMu.Lock()
	waitErr := c.waitErr
	expectedExit := c.expectedExit
	c.stateMu.Unlock()
	_ = c.stdoutPipe.Close()
	var exitError *exec.ExitError
	if waitErr != nil && (!errors.As(waitErr, &exitError) || !expectedExit) {
		return fmt.Errorf("wait for FYLO: %w", waitErr)
	}
	return nil
}

// Crash terminates and reaps the owned FYLO process without a graceful stdin
// shutdown. It exists for crash-recovery proving and must not be used as a
// normal lifecycle operation.
func (c *Client) Crash() error {
	<-c.requestGate
	defer func() { c.requestGate <- struct{}{} }()
	return c.terminate()
}

func normalizeConfig(config Config) (Config, error) {
	if config.Binary == "" {
		config.Binary = "fylo"
	}
	if config.Root == "" {
		return Config{}, errors.New("FYLO root is required")
	}
	absoluteRoot, err := filepath.Abs(config.Root)
	if err != nil {
		return Config{}, fmt.Errorf("resolve FYLO root: %w", err)
	}
	info, err := os.Stat(absoluteRoot)
	if err != nil {
		return Config{}, fmt.Errorf("inspect FYLO root: %w", err)
	}
	if !info.IsDir() {
		return Config{}, fmt.Errorf("FYLO root %q is not a directory", absoluteRoot)
	}
	config.Root = absoluteRoot
	if config.ExpectedProtocol == 0 {
		config.ExpectedProtocol = ProtocolVersion
	}
	if config.ExpectedProtocol < 1 {
		return Config{}, errors.New("expected FYLO protocol must be positive")
	}
	if config.ExpectedRuntimeVersion == "" {
		config.ExpectedRuntimeVersion = PhaseOneRuntimeVersion
	}
	if config.ExpectedBuildTarget == "" {
		config.ExpectedBuildTarget = localRuntimeTarget()
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = defaultMaxRequestBytes
	}
	if config.MaxRequestBytes < 1 {
		return Config{}, errors.New("FYLO request frame limit must be positive")
	}
	if config.MaxRequestBytes > maxMachineFrameBytes {
		return Config{}, fmt.Errorf(
			"FYLO request frame limit must not exceed %d bytes",
			maxMachineFrameBytes,
		)
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultMaxResponseBytes
	}
	if config.MaxResponseBytes < 1 {
		return Config{}, errors.New("FYLO response frame limit must be positive")
	}
	if config.MaxResponseBytes > maxMachineFrameBytes {
		return Config{}, fmt.Errorf(
			"FYLO response frame limit must not exceed %d bytes",
			maxMachineFrameBytes,
		)
	}
	if (config.EncryptionKey == "") != (config.SchemaDir == "") {
		return Config{}, errors.New("FYLO encryption requires both a schema directory and a key")
	}
	if config.EncryptionKey != "" && len(config.EncryptionKey) < 32 {
		return Config{}, errors.New("FYLO encryption key must be at least 32 characters")
	}
	if config.MaxDiagnosticBytes == 0 {
		config.MaxDiagnosticBytes = defaultMaxDiagnosticBytes
	}
	if config.MaxDiagnosticBytes < 1 {
		return Config{}, errors.New("FYLO diagnostic limit must be positive")
	}
	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = defaultShutdownTimeout
	}
	if config.ShutdownTimeout < 0 {
		return Config{}, errors.New("FYLO shutdown timeout must not be negative")
	}
	return config, nil
}

func validateRuntimeIdentity(identity RuntimeIdentity, config Config) error {
	checks := []struct {
		field    string
		expected string
		actual   string
	}{
		{
			field:    "runtimeVersion",
			expected: config.ExpectedRuntimeVersion,
			actual:   identity.RuntimeVersion,
		},
		{
			field:    "protocolVersion",
			expected: strconv.Itoa(config.ExpectedProtocol),
			actual:   strconv.Itoa(identity.ProtocolVersion),
		},
		{
			field:    "buildTarget",
			expected: config.ExpectedBuildTarget,
			actual:   identity.BuildTarget,
		},
		{
			field:    "dependencies.chex.requiredVersion",
			expected: requiredCHEXVersion,
			actual:   identity.Dependencies.CHEX.RequiredVersion,
		},
		{
			field:    "dependencies.ttid.requiredVersion",
			expected: requiredTTIDVersion,
			actual:   identity.Dependencies.TTID.RequiredVersion,
		},
		{
			field:    "machine.framing",
			expected: "ndjson",
			actual:   identity.Machine.Framing,
		},
		{
			field:    "machine.encoding",
			expected: "utf-8",
			actual:   identity.Machine.Encoding,
		},
		{
			field:    "machine.delimiter",
			expected: "LF",
			actual:   identity.Machine.Delimiter,
		},
		{
			field:    "machine.maxRequestBytes",
			expected: strconv.Itoa(config.MaxRequestBytes),
			actual:   strconv.Itoa(identity.Machine.MaxRequestBytes),
		},
		{
			field:    "machine.maxResponseBytes",
			expected: strconv.Itoa(config.MaxResponseBytes),
			actual:   strconv.Itoa(identity.Machine.MaxResponseBytes),
		},
		{
			field:    "machine.duplicateKeys",
			expected: "rejected",
			actual:   identity.Machine.DuplicateKeys,
		},
		{
			field:    "machine.truncatedFrame",
			expected: "error-and-terminate",
			actual:   identity.Machine.TruncatedFrame,
		},
		{
			field:    "machine.malformedFrame",
			expected: "error-and-resume-at-next-LF",
			actual:   identity.Machine.MalformedFrame,
		},
	}
	for _, check := range checks {
		if check.actual != check.expected {
			return runtimeMismatch(check.field, check.expected, check.actual)
		}
	}

	if identity.Machine.DelimiterCountsTowardLimit {
		return runtimeMismatch("machine.delimiterCountsTowardLimit", "false", "true")
	}
	if !identity.Capabilities.Handshake {
		return runtimeMismatch("capabilities.handshake", "true", "false")
	}
	if !identity.Capabilities.ExclusiveRoot {
		return runtimeMismatch("capabilities.exclusiveRoot", "true", "false")
	}
	pagination := identity.Capabilities.QueryPagination
	if pagination == nil {
		return runtimeMismatch("capabilities.queryPagination", "present", "missing")
	}
	if pagination.Version != 1 {
		return runtimeMismatch(
			"capabilities.queryPagination.version",
			"1",
			strconv.Itoa(pagination.Version),
		)
	}
	for _, required := range []string{"findDocs", "findDeletedDocs"} {
		if !slices.Contains(pagination.Operations, required) {
			return runtimeMismatch(
				"capabilities.queryPagination.operations",
				required,
				strings.Join(pagination.Operations, ","),
			)
		}
	}
	if pagination.MaxItems < 1 {
		return runtimeMismatch(
			"capabilities.queryPagination.maxItems",
			"positive",
			strconv.Itoa(pagination.MaxItems),
		)
	}
	if pagination.Ordering != "ttid-binary-ascending" {
		return runtimeMismatch(
			"capabilities.queryPagination.ordering",
			"ttid-binary-ascending",
			pagination.Ordering,
		)
	}
	if pagination.RestartPolicy != "restart-from-first-page" {
		return runtimeMismatch(
			"capabilities.queryPagination.restartPolicy",
			"restart-from-first-page",
			pagination.RestartPolicy,
		)
	}
	if !identity.Dependencies.CHEX.Available {
		return runtimeMismatch("dependencies.chex.available", "true", "false")
	}
	if !identity.Dependencies.TTID.Available {
		return runtimeMismatch("dependencies.ttid.available", "true", "false")
	}

	developmentBuild := strings.HasPrefix(identity.BuildKind, "development") ||
		identity.Commit == "" ||
		identity.Commit == "unknown"
	if developmentBuild && !config.AllowDevelopmentBuild {
		return runtimeMismatch(
			"buildKind",
			"release with an immutable commit",
			identity.BuildKind+" commit="+identity.Commit,
		)
	}
	if !developmentBuild && identity.BuildKind != "release" {
		return runtimeMismatch("buildKind", "release", identity.BuildKind)
	}
	return nil
}

func decodeRuntimeIdentity(data []byte) (RuntimeIdentity, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return RuntimeIdentity{}, err
	}
	if err := requireFields(root,
		"runtimeVersion",
		"protocolVersion",
		"commit",
		"buildTarget",
		"buildKind",
		"dependencies",
		"machine",
		"capabilities",
	); err != nil {
		return RuntimeIdentity{}, err
	}
	if err := requireNestedFields(root["dependencies"], "dependencies",
		"chex",
		"ttid",
	); err != nil {
		return RuntimeIdentity{}, err
	}
	var dependencies map[string]json.RawMessage
	if err := json.Unmarshal(root["dependencies"], &dependencies); err != nil {
		return RuntimeIdentity{}, fmt.Errorf("decode dependencies: %w", err)
	}
	for _, dependency := range []string{"chex", "ttid"} {
		if err := requireNestedFields(
			dependencies[dependency],
			"dependencies."+dependency,
			"requiredVersion",
			"available",
		); err != nil {
			return RuntimeIdentity{}, err
		}
	}
	if err := requireNestedFields(root["machine"], "machine",
		"framing",
		"encoding",
		"delimiter",
		"delimiterCountsTowardLimit",
		"maxRequestBytes",
		"maxResponseBytes",
		"duplicateKeys",
		"truncatedFrame",
		"malformedFrame",
	); err != nil {
		return RuntimeIdentity{}, err
	}
	if err := requireNestedFields(root["capabilities"], "capabilities",
		"handshake",
		"exclusiveRoot",
		"queryPagination",
	); err != nil {
		return RuntimeIdentity{}, err
	}

	var identity RuntimeIdentity
	if err := json.Unmarshal(data, &identity); err != nil {
		return RuntimeIdentity{}, err
	}
	return identity, nil
}

func requireNestedFields(data json.RawMessage, object string, fields ...string) error {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("decode %s: %w", object, err)
	}
	return requireFields(values, fields...)
}

func requireFields(values map[string]json.RawMessage, fields ...string) error {
	for _, field := range fields {
		value, exists := values[field]
		if !exists {
			return runtimeMismatch(field, "present", "missing")
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return runtimeMismatch(field, "non-null", "null")
		}
	}
	return nil
}

func runtimeMismatch(field, expected, actual string) error {
	return &RuntimeCompatibilityError{
		Field:    field,
		Expected: expected,
		Actual:   actual,
	}
}

func localRuntimeTarget() string {
	operatingSystem := runtime.GOOS
	if operatingSystem == "darwin" {
		operatingSystem = "macos"
	}
	return operatingSystem + "-" + runtime.GOARCH
}

type machineResponse struct {
	ProtocolVersion int             `json:"protocolVersion"`
	OK              bool            `json:"ok"`
	Operation       *string         `json:"op"`
	RequestID       *string         `json:"requestId"`
	DurationMS      int64           `json:"durationMs"`
	Result          json.RawMessage `json:"result,omitempty"`
	Failure         *machineError   `json:"error,omitempty"`
}

type machineError struct {
	Name    string `json:"name"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

func decodeResponse(frame []byte) (machineResponse, error) {
	if err := rejectDuplicateFields(frame); err != nil {
		return machineResponse{}, err
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(frame, &envelope); err != nil {
		return machineResponse{}, err
	}
	for _, required := range []string{
		"protocolVersion",
		"ok",
		"op",
		"requestId",
		"durationMs",
	} {
		value, exists := envelope[required]
		if !exists {
			return machineResponse{}, fmt.Errorf("FYLO response has no %s", required)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) &&
			required != "op" &&
			required != "requestId" {
			return machineResponse{}, fmt.Errorf("FYLO response field %s is null", required)
		}
	}

	var response machineResponse
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return machineResponse{}, err
	}
	if err := requireJSONEnd(decoder); err != nil {
		return machineResponse{}, err
	}
	if response.ProtocolVersion < 1 {
		return machineResponse{}, errors.New("FYLO response has no valid protocolVersion")
	}
	if response.DurationMS < 0 {
		return machineResponse{}, errors.New("FYLO response has a negative durationMs")
	}
	return response, nil
}

func rejectDuplicateFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := inspectJSONValue(decoder); err != nil {
		return err
	}
	return requireJSONEnd(decoder)
}

func inspectJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object contains a non-string field name")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := inspectJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("invalid JSON object terminator")
		}
	case '[':
		for decoder.More() {
			if err := inspectJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("invalid JSON array terminator")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func requireJSONEnd(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values in one FYLO frame")
		}
		return err
	}
	return nil
}

func (c *Client) readFrame() ([]byte, error) {
	var frame []byte
	for {
		fragment, err := c.stdout.ReadSlice('\n')
		frame = append(frame, fragment...)
		if len(frame) > c.config.MaxResponseBytes+1 {
			return nil, fmt.Errorf("response frame exceeds %d bytes", c.config.MaxResponseBytes)
		}
		switch {
		case err == nil:
			frame = bytes.TrimSuffix(frame, []byte{'\n'})
			if len(frame) == 0 {
				return nil, errors.New("empty response frame")
			}
			return frame, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return nil, err
		}
	}
}

func (c *Client) isClosed() bool {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.closed
}

func (c *Client) closedError() error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	diagnostics := c.Diagnostics()
	if c.waitErr != nil {
		if diagnostics != "" {
			return fmt.Errorf("%w: %v; diagnostics: %s", errClientClosed, c.waitErr, diagnostics)
		}
		return fmt.Errorf("%w: %v", errClientClosed, c.waitErr)
	}
	return errClientClosed
}

func (c *Client) terminate() error {
	c.stateMu.Lock()
	closed := c.closed
	c.expectedExit = true
	c.stateMu.Unlock()
	_ = c.stdin.Close()
	if !closed && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	<-c.waitDone
	_ = c.stdoutPipe.Close()
	return nil
}

func newRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

type tailBuffer struct {
	mu       sync.Mutex
	capacity int
	data     []byte
}

func newTailBuffer(capacity int) *tailBuffer {
	return &tailBuffer{capacity: capacity}
}

func (b *tailBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	written := len(data)
	if len(data) >= b.capacity {
		b.data = append(b.data[:0], data[len(data)-b.capacity:]...)
		return written, nil
	}
	excess := len(b.data) + len(data) - b.capacity
	if excess > 0 {
		copy(b.data, b.data[excess:])
		b.data = b.data[:len(b.data)-excess]
	}
	b.data = append(b.data, data...)
	return written, nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(bytes.Clone(b.data))
}
