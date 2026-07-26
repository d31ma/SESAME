// Package sesame provides a thin Go client for a local SESAME process.
//
// The client owns process lifecycle, NDJSON framing, cancellation, and typed
// transport errors. Authentication and authorization semantics remain in the
// SESAME executable.
package sesame

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	protocolVersion = "1"
	maxFrameBytes   = 1 << 20
	closeTimeout    = 2 * time.Second
)

// Options controls local SESAME process startup.
type Options struct {
	Binary string
	Stderr io.Writer

	// Deployment points at a directory created by sesame init and enables
	// verified snapshots. FYLOBinary and FYLORoot configure bare storage
	// without snapshots and must be set together. SESAME itself fails closed
	// on a half or conflicting configuration. Without any of them the child
	// runs without durable storage and tenant operations return
	// storage_not_configured.
	Deployment string
	FYLOBinary string
	FYLORoot   string

	// SkipCompatibilityCheck suppresses the protocol-version handshake Start
	// performs. It exists for tests that deliberately drive a mismatched or
	// non-conforming engine; production callers should leave it unset.
	SkipCompatibilityCheck bool
}

// Info describes a SESAME release binary and what it can be asked to do.
type Info struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuiltAt   string `json:"built_at"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	// ProtocolVersion is the machine protocol the engine speaks. A client
	// that speaks a different one cannot trust anything else in the frame.
	ProtocolVersion string `json:"protocol_version"`
	// Operations is every operation this engine routes, sorted.
	Operations []string `json:"operations"`
}

// ProtocolVersion is the machine protocol this client speaks.
const ProtocolVersion = protocolVersion

// ProtocolError is a stable error returned by the SESAME machine interface.
type ProtocolError struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Retryable bool           `json:"retryable"`
	Details   map[string]any `json:"details,omitempty"`
}

// Error implements error.
func (e *ProtocolError) Error() string {
	return fmt.Sprintf("sesame protocol error %s: %s", e.Code, e.Message)
}

// Client owns one long-lived local SESAME subprocess.
type Client struct {
	mu      sync.Mutex
	command *exec.Cmd
	stdin   io.WriteCloser
	stdout  *bufio.Scanner
	done    chan error
	closed  bool
}

// Start launches a SESAME subprocess in persistent machine mode.
func Start(ctx context.Context, options Options) (*Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	binary := options.Binary
	if binary == "" {
		// SESAME_BINARY names the engine when no option does; an explicit option still wins.
		binary = os.Getenv("SESAME_BINARY")
	}
	if binary == "" {
		binary = "sesame"
	}
	arguments := []string{"exec", "--loop"}
	if options.Deployment != "" {
		arguments = append(arguments, "--deployment", options.Deployment)
	}
	if options.FYLOBinary != "" || options.FYLORoot != "" {
		arguments = append(
			arguments,
			"--fylo-binary", options.FYLOBinary,
			"--fylo-root", options.FYLORoot,
		)
	}
	command := exec.Command(binary, arguments...)
	// When the caller wants diagnostics, they get all of them. Otherwise the
	// startup window is captured and the rest discarded: the engine refuses a
	// missing deployment or an unusable FYLO root by writing why to stderr and
	// exiting, and discarding that turns an actionable message into "the
	// process died". After Start returns, a long-running engine's diagnostics
	// are the host's business and are not accumulated here.
	startup := &startupDiagnostics{}
	if options.Stderr != nil {
		command.Stderr = options.Stderr
	} else {
		command.Stderr = startup
	}

	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("open sesame stdin: %w", err)
	}
	stdoutPipe, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("open sesame stdout: %w", err)
	}
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("start sesame: %w", err)
	}

	scanner := bufio.NewScanner(stdoutPipe)
	scanner.Buffer(make([]byte, 64*1024), maxFrameBytes)
	client := &Client{
		command: command,
		stdin:   stdin,
		stdout:  scanner,
		done:    make(chan error, 1),
	}
	go func() {
		client.done <- command.Wait()
	}()

	// A mismatched engine is discovered here rather than partway through a
	// security flow that then cannot finish. This costs one local round trip
	// on a pipe; system.version needs no storage, so it works even when the
	// child is running without a configured FYLO root.
	if !options.SkipCompatibilityCheck {
		if err := client.checkCompatibility(ctx); err != nil {
			_ = client.Close()
			return nil, startup.wrap(err)
		}
	}
	startup.stop()
	return client, nil
}

// startupDiagnosticsBytes bounds what a failing engine can make the caller
// hold. It is generous enough for a refusal and its remedy, and far short of
// anything worth worrying about.
const startupDiagnosticsBytes = 4096

// startupDiagnostics captures the beginning of the engine's stderr so a
// startup failure can explain itself, then stops caring once the engine is up.
type startupDiagnostics struct {
	mu       sync.Mutex
	captured []byte
	stopped  bool
}

func (d *startupDiagnostics) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if remaining := startupDiagnosticsBytes - len(d.captured); !d.stopped && remaining > 0 {
		if len(p) < remaining {
			remaining = len(p)
		}
		d.captured = append(d.captured, p[:remaining]...)
	}
	// Always report the full write: refusing bytes would make the engine block
	// on a stderr it cannot drain.
	return len(p), nil
}

func (d *startupDiagnostics) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopped = true
	d.captured = nil
}

// wrap attaches what the engine said to why the client could not start.
func (d *startupDiagnostics) wrap(err error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	diagnostic := strings.TrimSpace(string(d.captured))
	if diagnostic == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, diagnostic)
}

// IncompatibleEngineError reports a SESAME binary this client cannot speak to.
//
// It names both sides, because the fix is always to change one of them and the
// operator needs to know which is which.
type IncompatibleEngineError struct {
	ClientProtocolVersion string
	EngineProtocolVersion string
	EngineVersion         string
	MissingOperations     []string
}

func (e *IncompatibleEngineError) Error() string {
	if e.EngineProtocolVersion != e.ClientProtocolVersion {
		return fmt.Sprintf(
			"sesame engine %s speaks machine protocol %q; this client speaks %q",
			e.EngineVersion, e.EngineProtocolVersion, e.ClientProtocolVersion)
	}
	return fmt.Sprintf(
		"sesame engine %s does not support %d operation(s) this client requires: %s",
		e.EngineVersion, len(e.MissingOperations), strings.Join(e.MissingOperations, ", "))
}

// checkCompatibility asks the engine what it is and what it routes.
//
// The protocol version is the hard gate: a different version means the framing
// or the envelope may differ, so nothing further can be trusted. The operation
// list is advisory here — Start does not require every operation this client
// knows, because an older engine that lacks one an application never calls is
// perfectly usable. RequireOperations exists for applications that would
// rather find out immediately.
func (c *Client) checkCompatibility(ctx context.Context) error {
	version, err := c.Version(ctx)
	if err != nil {
		return fmt.Errorf("verify sesame compatibility: %w", err)
	}
	if version.ProtocolVersion != protocolVersion {
		return &IncompatibleEngineError{
			ClientProtocolVersion: protocolVersion,
			EngineProtocolVersion: version.ProtocolVersion,
			EngineVersion:         version.Version,
		}
	}
	return nil
}

// RequireOperations fails unless the engine routes every named operation.
//
// Call it at startup with the operations an application actually depends on.
// Finding out here beats finding out from an operation_not_found in the middle
// of a login.
func (c *Client) RequireOperations(ctx context.Context, operations ...string) error {
	version, err := c.Version(ctx)
	if err != nil {
		return fmt.Errorf("verify sesame operations: %w", err)
	}
	routed := make(map[string]struct{}, len(version.Operations))
	for _, operation := range version.Operations {
		routed[operation] = struct{}{}
	}
	var missing []string
	for _, operation := range operations {
		if _, ok := routed[operation]; !ok {
			missing = append(missing, operation)
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		return &IncompatibleEngineError{
			ClientProtocolVersion: protocolVersion,
			EngineProtocolVersion: version.ProtocolVersion,
			EngineVersion:         version.Version,
			MissingOperations:     missing,
		}
	}
	return nil
}

// Ping verifies that the child process can answer a machine request.
func (c *Client) Ping(ctx context.Context) error {
	var status struct {
		Status string `json:"status"`
	}
	if err := c.Request(ctx, "system.ping", struct{}{}, &status); err != nil {
		return err
	}
	if status.Status != "ok" {
		return fmt.Errorf("unexpected sesame liveness status %q", status.Status)
	}
	return nil
}

// Version returns metadata for the child SESAME binary.
func (c *Client) Version(ctx context.Context) (Info, error) {
	var info Info
	if err := c.Request(ctx, "system.version", struct{}{}, &info); err != nil {
		return Info{}, err
	}
	return info, nil
}

// Tenant is one tenant as reported by the SESAME engine.
type Tenant struct {
	ID     string `json:"tenant_id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// TenantBootstrapResult reports a tenant.bootstrap outcome.
type TenantBootstrapResult struct {
	Tenant  Tenant `json:"tenant"`
	Created bool   `json:"created"`
}

// TenantBootstrap creates the named tenant exactly once. Repeating the call
// with the same name returns the existing tenant with Created false, so it is
// safe to retry.
func (c *Client) TenantBootstrap(ctx context.Context, name string) (TenantBootstrapResult, error) {
	var result TenantBootstrapResult
	if err := c.Request(ctx, "tenant.bootstrap", map[string]string{"name": name}, &result); err != nil {
		return TenantBootstrapResult{}, err
	}
	return result, nil
}

// TenantGetByName returns one tenant by normalized name.
func (c *Client) TenantGetByName(ctx context.Context, name string) (Tenant, error) {
	var result Tenant
	if err := c.Request(ctx, "tenant.get", map[string]string{"name": name}, &result); err != nil {
		return Tenant{}, err
	}
	return result, nil
}

// TenantGetByID returns one tenant by public identifier.
func (c *Client) TenantGetByID(ctx context.Context, tenantID string) (Tenant, error) {
	var result Tenant
	if err := c.Request(ctx, "tenant.get", map[string]string{"tenant_id": tenantID}, &result); err != nil {
		return Tenant{}, err
	}
	return result, nil
}

// Principal is one principal as reported by the SESAME engine.
type Principal struct {
	ID         string              `json:"principal_id"`
	TenantID   string              `json:"tenant_id"`
	Kind       string              `json:"kind"`
	Status     string              `json:"status"`
	Identifier PrincipalIdentifier `json:"identifier"`
}

// PrincipalIdentifier locates a principal inside one tenant-scoped namespace.
type PrincipalIdentifier struct {
	Namespace string `json:"namespace"`
	Value     string `json:"value"`
}

// PrincipalCreate registers a principal and atomically claims its first
// identifier.
func (c *Client) PrincipalCreate(
	ctx context.Context,
	tenantID string,
	kind string,
	identifier PrincipalIdentifier,
) (Principal, error) {
	var result Principal
	if err := c.Request(ctx, "principal.create", map[string]string{
		"tenant_id":            tenantID,
		"kind":                 kind,
		"identifier_namespace": identifier.Namespace,
		"identifier_value":     identifier.Value,
	}, &result); err != nil {
		return Principal{}, err
	}
	return result, nil
}

// PrincipalGetByID returns one principal by public identifier.
func (c *Client) PrincipalGetByID(ctx context.Context, principalID string) (Principal, error) {
	var result Principal
	if err := c.Request(ctx, "principal.get", map[string]string{
		"principal_id": principalID,
	}, &result); err != nil {
		return Principal{}, err
	}
	return result, nil
}

// PrincipalGetByIdentifier resolves a normalized identifier inside one tenant
// and namespace.
func (c *Client) PrincipalGetByIdentifier(
	ctx context.Context,
	tenantID string,
	identifier PrincipalIdentifier,
) (Principal, error) {
	var result Principal
	if err := c.Request(ctx, "principal.get", map[string]string{
		"tenant_id":            tenantID,
		"identifier_namespace": identifier.Namespace,
		"identifier_value":     identifier.Value,
	}, &result); err != nil {
		return Principal{}, err
	}
	return result, nil
}

// PrincipalSuspend durably suspends a principal; repeating it is safe.
func (c *Client) PrincipalSuspend(ctx context.Context, principalID string) (Principal, error) {
	var result Principal
	if err := c.Request(ctx, "principal.suspend", map[string]string{
		"principal_id": principalID,
	}, &result); err != nil {
		return Principal{}, err
	}
	return result, nil
}

// Permission pairs one action pattern with one resource pattern, optionally
// requiring context attributes to equal exact values.
type Permission struct {
	Action     string            `json:"action"`
	Resource   string            `json:"resource"`
	Conditions map[string]string `json:"conditions,omitempty"`
}

// Role is an immutable named permission set inside one tenant.
type Role struct {
	ID          string       `json:"role_id"`
	TenantID    string       `json:"tenant_id"`
	Name        string       `json:"name"`
	Permissions []Permission `json:"permissions"`
}

// Grant assigns one role to one principal.
type Grant struct {
	ID          string `json:"grant_id"`
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id,omitempty"`
	GroupID     string `json:"group_id,omitempty"`
	RoleID      string `json:"role_id"`
}

// DecisionRequest names one concrete authorization question.
type DecisionRequest struct {
	TenantID    string            `json:"tenant_id"`
	PrincipalID string            `json:"principal_id"`
	Action      string            `json:"action"`
	Resource    string            `json:"resource"`
	Context     map[string]string `json:"context,omitempty"`
	// SessionID and SessionSecret let the engine derive trusted context,
	// including session.assurance for step-up conditions.
	SessionID     string `json:"session_id,omitempty"`
	SessionSecret string `json:"session_secret,omitempty"`
}

// Decision is one deterministic authorization answer.
type Decision struct {
	DecisionID    string `json:"decision_id"`
	Decision      string `json:"decision"`
	ReasonCode    string `json:"reason_code"`
	PolicyVersion int64  `json:"policy_version"`
	MissingKey    string `json:"missing_context_key,omitempty"`
}

// RoleCreate defines an immutable role with tenant-unique name.
func (c *Client) RoleCreate(
	ctx context.Context,
	tenantID string,
	name string,
	permissions []Permission,
) (Role, error) {
	var result Role
	if err := c.Request(ctx, "role.create", map[string]any{
		"tenant_id":   tenantID,
		"name":        name,
		"permissions": permissions,
	}, &result); err != nil {
		return Role{}, err
	}
	return result, nil
}

// GrantCreate assigns a role to a principal.
func (c *Client) GrantCreate(ctx context.Context, tenantID, principalID, roleID string) (Grant, error) {
	var result Grant
	if err := c.Request(ctx, "grant.create", map[string]string{
		"tenant_id":    tenantID,
		"principal_id": principalID,
		"role_id":      roleID,
	}, &result); err != nil {
		return Grant{}, err
	}
	return result, nil
}

// GrantRevoke durably removes a grant.
func (c *Client) GrantRevoke(ctx context.Context, grantID string) error {
	var result struct {
		Revoked bool `json:"revoked"`
	}
	return c.Request(ctx, "grant.revoke", map[string]string{"grant_id": grantID}, &result)
}

// Decide answers one authorization question with default deny. A non-nil
// policyVersion pins the decision and fails closed when it is not current.
func (c *Client) Decide(
	ctx context.Context,
	request DecisionRequest,
	policyVersion *int64,
) (Decision, error) {
	parameters := map[string]any{
		"tenant_id":    request.TenantID,
		"principal_id": request.PrincipalID,
		"action":       request.Action,
		"resource":     request.Resource,
	}
	// A session lets the engine derive assurance rather than trusting the
	// caller, which is what makes a step-up condition meaningful.
	if request.SessionID != "" {
		parameters["session_id"] = request.SessionID
		parameters["session_secret"] = request.SessionSecret
	}
	if len(request.Context) != 0 {
		parameters["context"] = request.Context
	}
	if policyVersion != nil {
		parameters["policy_version"] = *policyVersion
	}
	var result Decision
	if err := c.Request(ctx, "authorize.decide", parameters, &result); err != nil {
		return Decision{}, err
	}
	return result, nil
}

// DecideBatch answers a bounded batch of questions under one policy version.
func (c *Client) DecideBatch(
	ctx context.Context,
	requests []DecisionRequest,
	policyVersion *int64,
) ([]Decision, error) {
	parameters := map[string]any{"requests": requests}
	if policyVersion != nil {
		parameters["policy_version"] = *policyVersion
	}
	var result struct {
		Decisions []Decision `json:"decisions"`
	}
	if err := c.Request(ctx, "authorize.decide_batch", parameters, &result); err != nil {
		return nil, err
	}
	return result.Decisions, nil
}

// Group is a named set of principals inside one tenant.
type Group struct {
	ID       string `json:"group_id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
}

// AdminBootstrapResult reports what an administrator bootstrap converged to.
type AdminBootstrapResult struct {
	Tenant        Tenant    `json:"tenant"`
	Role          Role      `json:"role"`
	Administrator Principal `json:"administrator"`
	Grant         Grant     `json:"grant"`
	Created       bool      `json:"created"`
}

// AdminBootstrap converges the deployment to one administrator. It is safe
// to retry: an unchanged deployment appends no events.
func (c *Client) AdminBootstrap(
	ctx context.Context,
	tenantName string,
	identifier PrincipalIdentifier,
) (AdminBootstrapResult, error) {
	var result AdminBootstrapResult
	if err := c.Request(ctx, "admin.bootstrap", map[string]string{
		"tenant_name":          tenantName,
		"identifier_namespace": identifier.Namespace,
		"identifier_value":     identifier.Value,
	}, &result); err != nil {
		return AdminBootstrapResult{}, err
	}
	return result, nil
}

// GroupCreate defines a named group with a tenant-unique name.
func (c *Client) GroupCreate(ctx context.Context, tenantID, name string) (Group, error) {
	var result Group
	if err := c.Request(ctx, "group.create", map[string]string{
		"tenant_id": tenantID,
		"name":      name,
	}, &result); err != nil {
		return Group{}, err
	}
	return result, nil
}

// GroupMemberAdd records a principal joining a group.
func (c *Client) GroupMemberAdd(ctx context.Context, groupID, principalID string) error {
	var result struct {
		Member bool `json:"member"`
	}
	return c.Request(ctx, "group.member_add", map[string]string{
		"group_id":     groupID,
		"principal_id": principalID,
	}, &result)
}

// GroupMemberRemove durably removes a principal from a group.
func (c *Client) GroupMemberRemove(ctx context.Context, groupID, principalID string) error {
	var result struct {
		Member bool `json:"member"`
	}
	return c.Request(ctx, "group.member_remove", map[string]string{
		"group_id":     groupID,
		"principal_id": principalID,
	}, &result)
}

// GrantCreateForGroup assigns a role to every member of a group.
func (c *Client) GrantCreateForGroup(ctx context.Context, tenantID, groupID, roleID string) (Grant, error) {
	var result Grant
	if err := c.Request(ctx, "grant.create", map[string]string{
		"tenant_id": tenantID,
		"group_id":  groupID,
		"role_id":   roleID,
	}, &result); err != nil {
		return Grant{}, err
	}
	return result, nil
}

// AuthenticationResult reports the state of a login transaction.
type AuthenticationResult struct {
	TransactionID string `json:"transaction_id"`
	State         string `json:"state"`
	Assurance     string `json:"assurance,omitempty"`
	FailureCode   string `json:"failure_code,omitempty"`
	AttemptsLeft  int    `json:"attempts_left"`
}

// IssuedSession is returned once, at completion. Secret is the only copy.
type IssuedSession struct {
	SessionID   string `json:"session_id"`
	Secret      string `json:"session_secret"`
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id"`
	ExpiresAt   string `json:"expires_at"`
	Assurance   string `json:"assurance"`
}

// Session is a bounded authenticated context. It never carries the secret.
type Session struct {
	ID          string `json:"session_id"`
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id"`
	Status      string `json:"status"`
	IssuedAt    string `json:"issued_at"`
	ExpiresAt   string `json:"expires_at"`
	Assurance   string `json:"assurance"`
}

// SetPassword stores a password verifier for a principal.
func (c *Client) SetPassword(ctx context.Context, principalID, password string) error {
	var result struct {
		PasswordSet bool `json:"password_set"`
	}
	return c.Request(ctx, "authenticator.set_password", map[string]string{
		"principal_id": principalID,
		"password":     password,
	}, &result)
}

// AuthenticationBegin starts a login transaction. It succeeds whether or not
// the identifier resolves, so its result never reveals which identifiers
// exist.
func (c *Client) AuthenticationBegin(
	ctx context.Context,
	tenantID string,
	identifier PrincipalIdentifier,
) (AuthenticationResult, error) {
	var result AuthenticationResult
	if err := c.Request(ctx, "authn.begin", map[string]string{
		"tenant_id":            tenantID,
		"identifier_namespace": identifier.Namespace,
		"identifier_value":     identifier.Value,
	}, &result); err != nil {
		return AuthenticationResult{}, err
	}
	return result, nil
}

// AuthenticationVerifyPassword supplies a password to a running transaction.
func (c *Client) AuthenticationVerifyPassword(
	ctx context.Context,
	transactionID, password string,
) (AuthenticationResult, error) {
	var result AuthenticationResult
	if err := c.Request(ctx, "authn.verify_password", map[string]string{
		"transaction_id": transactionID,
		"password":       password,
	}, &result); err != nil {
		return AuthenticationResult{}, err
	}
	return result, nil
}

// AuthenticationComplete issues a session for a satisfied transaction. A zero
// lifetime uses the engine default.
func (c *Client) AuthenticationComplete(
	ctx context.Context,
	transactionID string,
	lifetime time.Duration,
) (IssuedSession, error) {
	var result IssuedSession
	if err := c.Request(ctx, "authn.complete", map[string]any{
		"transaction_id":   transactionID,
		"lifetime_seconds": int64(lifetime / time.Second),
	}, &result); err != nil {
		return IssuedSession{}, err
	}
	return result, nil
}

// TOTPEnrollment is returned once, at enrollment. The secret and URI are the
// only copies.
type TOTPEnrollment struct {
	Secret          string `json:"secret"`
	ProvisioningURI string `json:"provisioning_uri"`
}

// TOTPEnroll issues a TOTP shared secret. The authenticator is not usable
// until TOTPActivate proves a code.
func (c *Client) TOTPEnroll(ctx context.Context, principalID, issuer string) (TOTPEnrollment, error) {
	var result TOTPEnrollment
	if err := c.Request(ctx, "authenticator.totp_enroll", map[string]string{
		"principal_id": principalID,
		"issuer":       issuer,
	}, &result); err != nil {
		return TOTPEnrollment{}, err
	}
	return result, nil
}

// TOTPActivate proves an enrollment and makes the factor usable.
func (c *Client) TOTPActivate(ctx context.Context, principalID, code string) error {
	var result struct {
		Activated bool `json:"activated"`
	}
	return c.Request(ctx, "authenticator.totp_activate", map[string]string{
		"principal_id": principalID,
		"code":         code,
	}, &result)
}

// AuthenticationVerifyTOTP supplies a TOTP code to a transaction that has
// already satisfied a first factor, raising its assurance to MFA.
func (c *Client) AuthenticationVerifyTOTP(
	ctx context.Context,
	transactionID, code string,
) (AuthenticationResult, error) {
	var result AuthenticationResult
	if err := c.Request(ctx, "authn.verify_totp", map[string]string{
		"transaction_id": transactionID,
		"code":           code,
	}, &result); err != nil {
		return AuthenticationResult{}, err
	}
	return result, nil
}

// RecoveryCodeSet is returned once, at issue. The codes are the only copies.
type RecoveryCodeSet struct {
	Codes []string `json:"codes"`
}

// RecoveryCodesIssue generates a fresh set, retiring any previous one.
func (c *Client) RecoveryCodesIssue(ctx context.Context, principalID string) (RecoveryCodeSet, error) {
	var result RecoveryCodeSet
	if err := c.Request(ctx, "authenticator.recovery_codes_issue", map[string]string{
		"principal_id": principalID,
	}, &result); err != nil {
		return RecoveryCodeSet{}, err
	}
	return result, nil
}

// AuthenticationVerifyRecoveryCode spends one recovery code as a second
// factor, for when the TOTP device is gone.
func (c *Client) AuthenticationVerifyRecoveryCode(
	ctx context.Context,
	transactionID, code string,
) (AuthenticationResult, error) {
	var result AuthenticationResult
	if err := c.Request(ctx, "authn.verify_recovery_code", map[string]string{
		"transaction_id": transactionID,
		"code":           code,
	}, &result); err != nil {
		return AuthenticationResult{}, err
	}
	return result, nil
}

// SessionVerify checks a presented session secret.
func (c *Client) SessionVerify(ctx context.Context, sessionID, secret string) (Session, error) {
	var result Session
	if err := c.Request(ctx, "session.verify", map[string]string{
		"session_id":     sessionID,
		"session_secret": secret,
	}, &result); err != nil {
		return Session{}, err
	}
	return result, nil
}

// SessionRevoke durably ends a session; repeating it is safe.
func (c *Client) SessionRevoke(ctx context.Context, sessionID, reason string) error {
	var result struct {
		Revoked bool `json:"revoked"`
	}
	return c.Request(ctx, "session.revoke", map[string]string{
		"session_id": sessionID,
		"reason":     reason,
	}, &result)
}

// OIDCClient is one registered relying party. It never carries secret
// material.
type OIDCClient struct {
	ID           string   `json:"client_id"`
	TenantID     string   `json:"tenant_id"`
	Name         string   `json:"name"`
	Type         string   `json:"client_type"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	// Audience is "first_party" or "third_party". A third-party client
	// additionally needs recorded consent from the principal before an
	// authorization code is issued.
	Audience string `json:"audience"`
	// PostLogoutRedirectURIs are the only places a logout may return to,
	// matched exactly.
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
	Disabled               bool     `json:"disabled,omitempty"`
}

// ClientRegistration is a new client plus, for a confidential client, the
// only copy of its secret that will ever exist.
type ClientRegistration struct {
	Client OIDCClient `json:"client"`
	Secret string     `json:"client_secret,omitempty"`
}

// ClientRegister registers a relying party. Redirect URIs are matched exactly,
// so every URI a client may be sent back to must be listed here.
//
// audience is "first_party" or "third_party". An empty audience is treated as
// third party, which is the stricter rule: the client will need recorded user
// consent before it can receive an authorization code.
func (c *Client) ClientRegister(
	ctx context.Context,
	tenantID, name, clientType string,
	redirectURIs, scopes []string,
	audience string,
	postLogoutRedirectURIs []string,
) (ClientRegistration, error) {
	var result ClientRegistration
	if err := c.Request(ctx, "oidc_client.register", map[string]any{
		"tenant_id":                 tenantID,
		"name":                      name,
		"client_type":               clientType,
		"redirect_uris":             redirectURIs,
		"scopes":                    scopes,
		"audience":                  audience,
		"post_logout_redirect_uris": postLogoutRedirectURIs,
	}, &result); err != nil {
		return ClientRegistration{}, err
	}
	return result, nil
}

// LogoutResult reports what a host should do after an RP-initiated logout.
type LogoutResult struct {
	RedirectURI    string `json:"redirect_uri,omitempty"`
	State          string `json:"state,omitempty"`
	ClientID       string `json:"client_id"`
	PrincipalID    string `json:"principal_id"`
	SessionID      string `json:"session_id"`
	SessionRevoked bool   `json:"session_revoked"`
}

// Logout ends the session an ID token was issued against, which also ends
// every refresh grant resting on it. The hint is required: SESAME holds no
// browser session of its own. An expired hint is accepted.
func (c *Client) Logout(ctx context.Context, idTokenHint, postLogoutRedirectURI, state string) (LogoutResult, error) {
	var result LogoutResult
	if err := c.Request(ctx, "oidc.logout", map[string]string{
		"id_token_hint":            idTokenHint,
		"post_logout_redirect_uri": postLogoutRedirectURI,
		"state":                    state,
	}, &result); err != nil {
		return LogoutResult{}, err
	}
	return result, nil
}

// Consent is one principal's standing agreement for one client.
type Consent struct {
	PrincipalID string   `json:"principal_id"`
	ClientID    string   `json:"client_id"`
	TenantID    string   `json:"tenant_id"`
	Scopes      []string `json:"scopes"`
	GrantedAt   string   `json:"granted_at"`
	Withdrawn   bool     `json:"withdrawn,omitempty"`
}

// ConsentGrant records a principal agreeing that one client may hold one scope
// set. The session proves who is agreeing, so the caller cannot consent on
// somebody else's behalf. Re-granting merges with the existing set.
func (c *Client) ConsentGrant(
	ctx context.Context,
	sessionID, sessionSecret, clientID string,
	scopes []string,
) (Consent, error) {
	var result Consent
	if err := c.Request(ctx, "oidc.consent_grant", map[string]any{
		"session_id":     sessionID,
		"session_secret": sessionSecret,
		"client_id":      clientID,
		"scopes":         scopes,
	}, &result); err != nil {
		return Consent{}, err
	}
	return result, nil
}

// ConsentWithdraw durably ends an agreement and revokes every refresh family
// the client holds for this principal. Repeating it is safe.
func (c *Client) ConsentWithdraw(ctx context.Context, principalID, clientID string) error {
	var result struct {
		Withdrawn bool `json:"withdrawn"`
	}
	return c.Request(ctx, "oidc.consent_withdraw", map[string]string{
		"principal_id": principalID,
		"client_id":    clientID,
	}, &result)
}

// ConsentGet returns one standing agreement.
func (c *Client) ConsentGet(ctx context.Context, principalID, clientID string) (Consent, error) {
	var result Consent
	if err := c.Request(ctx, "oidc.consent_get", map[string]string{
		"principal_id": principalID,
		"client_id":    clientID,
	}, &result); err != nil {
		return Consent{}, err
	}
	return result, nil
}

// ClientGet returns one registered client.
func (c *Client) ClientGet(ctx context.Context, clientID string) (OIDCClient, error) {
	var result OIDCClient
	if err := c.Request(ctx, "oidc_client.get", map[string]string{"client_id": clientID}, &result); err != nil {
		return OIDCClient{}, err
	}
	return result, nil
}

// ClientRotateSecret issues a new client secret and invalidates the previous
// one at the same moment.
func (c *Client) ClientRotateSecret(ctx context.Context, clientID string) (string, error) {
	var result struct {
		Secret string `json:"client_secret"`
	}
	if err := c.Request(ctx, "oidc_client.rotate_secret", map[string]string{"client_id": clientID}, &result); err != nil {
		return "", err
	}
	return result.Secret, nil
}

// ClientDisable durably stops a client; repeating it is safe.
func (c *Client) ClientDisable(ctx context.Context, clientID, reason string) error {
	var result struct {
		Disabled bool `json:"disabled"`
	}
	return c.Request(ctx, "oidc_client.disable", map[string]string{
		"client_id": clientID,
		"reason":    reason,
	}, &result)
}

// AuthorizationRequest is a browser authorization request handed to the
// engine for validation. PKCE is required: CodeChallenge must be the
// base64url SHA-256 of the verifier and the method must be "S256".
type AuthorizationRequest struct {
	ClientID            string   `json:"client_id"`
	RedirectURI         string   `json:"redirect_uri"`
	ResponseType        string   `json:"response_type"`
	Scopes              []string `json:"scopes"`
	State               string   `json:"state,omitempty"`
	Nonce               string   `json:"nonce,omitempty"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
	// RequestURI carries a reference returned by PushedAuthorizationStart.
	// When it is set, every other field except ClientID must be empty: the
	// engine refuses a request that mixes the two rather than merging them.
	RequestURI string `json:"request_uri,omitempty"`
}

// PushedRequest is a stored authorization request awaiting a browser.
type PushedRequest struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

// StartedInteraction is what a host needs to run its own login step.
type StartedInteraction struct {
	InteractionID string   `json:"interaction_id"`
	Secret        string   `json:"interaction_secret"`
	TenantID      string   `json:"tenant_id"`
	ClientID      string   `json:"client_id"`
	ClientName    string   `json:"client_name"`
	Scopes        []string `json:"scopes"`
	ExpiresAt     string   `json:"expires_at"`
}

// AuthorizationResponse is what the host redirects the browser to.
type AuthorizationResponse struct {
	RedirectURI string `json:"redirect_uri"`
	Code        string `json:"code"`
	State       string `json:"state,omitempty"`
}

// TokenRequest is a back-channel token request. Code, RedirectURI, and
// CodeVerifier belong to the authorization code grant; RefreshToken and Scope
// belong to the refresh grant.
type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	CodeVerifier string `json:"code_verifier,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	// Scope may narrow the granted set on a refresh. It can never widen it.
	Scope string `json:"scope,omitempty"`
	// DPoPProof binds the issued tokens to a client key (RFC 9449). Leave it
	// empty for ordinary bearer tokens.
	//
	// DPoPMethod and DPoPURI are the HTTP request your handler actually
	// served. SESAME speaks no HTTP and cannot observe them, so reporting them
	// wrongly defeats the binding — pass what the request really was.
	DPoPProof  string `json:"dpop_proof,omitempty"`
	DPoPMethod string `json:"http_method,omitempty"`
	DPoPURI    string `json:"http_uri,omitempty"`
}

// TokenResponse is the issued token set. RefreshToken is present only when
// the grant carries offline_access, and it changes on every refresh: the
// value returned here replaces the one that was presented.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// RefreshFamily is one rotating family of refresh tokens. It carries no token
// material.
type RefreshFamily struct {
	ID        string `json:"family_id"`
	TenantID  string `json:"tenant_id"`
	ClientID  string `json:"client_id"`
	SessionID string `json:"session_id"`
	StartedAt string `json:"started_at"`
	ExpiresAt string `json:"expires_at"`
	Revoked   bool   `json:"revoked,omitempty"`
	Reason    string `json:"revoked_reason,omitempty"`
}

// RefreshFamilyRevoke durably ends every refresh token descended from one
// authorization. Repeating it is safe.
func (c *Client) RefreshFamilyRevoke(ctx context.Context, familyID, reason string) error {
	var result struct {
		Revoked bool `json:"revoked"`
	}
	return c.Request(ctx, "oidc.refresh_family_revoke", map[string]string{
		"family_id": familyID,
		"reason":    reason,
	}, &result)
}

// RefreshFamilyGet returns one family for diagnosis.
func (c *Client) RefreshFamilyGet(ctx context.Context, familyID string) (RefreshFamily, error) {
	var result RefreshFamily
	if err := c.Request(ctx, "oidc.refresh_family_get", map[string]string{"family_id": familyID}, &result); err != nil {
		return RefreshFamily{}, err
	}
	return result, nil
}

// Authorize validates a browser authorization request and starts the
// interaction the host will drive. Nothing should be shown to a user before
// this succeeds.
func (c *Client) Authorize(ctx context.Context, request AuthorizationRequest) (StartedInteraction, error) {
	var result StartedInteraction
	if err := c.Request(ctx, "oidc.authorize", request, &result); err != nil {
		return StartedInteraction{}, err
	}
	return result, nil
}

// InteractionComplete exchanges proof of an authenticated session for the
// authorization code. The redirect URI in the response is the validated one
// from the original request, not anything supplied here.
func (c *Client) InteractionComplete(
	ctx context.Context,
	interactionID, interactionSecret, sessionID, sessionSecret string,
) (AuthorizationResponse, error) {
	var result AuthorizationResponse
	if err := c.Request(ctx, "oidc.interaction_complete", map[string]string{
		"interaction_id":     interactionID,
		"interaction_secret": interactionSecret,
		"session_id":         sessionID,
		"session_secret":     sessionSecret,
	}, &result); err != nil {
		return AuthorizationResponse{}, err
	}
	return result, nil
}

// Interaction is one persisted authorization request, without its digests.
type Interaction struct {
	ID          string   `json:"interaction_id"`
	TenantID    string   `json:"tenant_id"`
	ClientID    string   `json:"client_id"`
	RedirectURI string   `json:"redirect_uri"`
	Scopes      []string `json:"scopes"`
	Status      string   `json:"status"`
	ExpiresAt   string   `json:"expires_at"`
}

// InteractionGet returns one interaction, so a host can render a consent
// screen naming the scopes actually requested.
func (c *Client) InteractionGet(ctx context.Context, interactionID string) (Interaction, error) {
	var result Interaction
	if err := c.Request(ctx, "oidc.interaction_get",
		map[string]string{"interaction_id": interactionID}, &result); err != nil {
		return Interaction{}, err
	}
	return result, nil
}

// TokenExchange redeems an authorization code or a refresh token. Both are
// single use: a refresh returns a successor that replaces the token presented,
// and presenting a spent one revokes the whole family.
// DPoPVerification is what a resource server learns about a key-bound token.
type DPoPVerification struct {
	Active      bool     `json:"active"`
	TenantID    string   `json:"tenant_id,omitempty"`
	PrincipalID string   `json:"principal_id,omitempty"`
	ClientID    string   `json:"client_id,omitempty"`
	SessionID   string   `json:"session_id,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	Thumbprint  string   `json:"dpop_thumbprint,omitempty"`
	ExpiresAt   int64    `json:"expires_at,omitempty"`
}

// DPoPVerify checks a key-bound access token against a fresh proof (RFC 9449).
//
// method and uri are the HTTP request your handler actually served. The engine
// speaks no HTTP and cannot observe them, so reporting them wrongly defeats the
// binding — pass what the request really was, not what it should have been.
func (c *Client) DPoPVerify(
	ctx context.Context,
	accessToken, proof, method, uri string,
) (DPoPVerification, error) {
	var result DPoPVerification
	if err := c.Request(ctx, "oidc.dpop_verify", map[string]any{
		"access_token": accessToken,
		"dpop_proof":   proof,
		"http_method":  method,
		"http_uri":     uri,
	}, &result); err != nil {
		return DPoPVerification{}, err
	}
	return result, nil
}

// PushedAuthorizationStart pushes an authorization request on the back
// channel (RFC 9126) and returns the single-use reference to redirect with.
//
// Everything the flow depends on is validated and stored here, so what the
// user agent carries afterwards is one opaque string with nothing in it to
// edit.
func (c *Client) PushedAuthorizationStart(
	ctx context.Context,
	request AuthorizationRequest,
	clientSecret string,
) (PushedRequest, error) {
	var result PushedRequest
	if err := c.Request(ctx, "oidc.pushed_authorize", struct {
		AuthorizationRequest
		ClientSecret string `json:"client_secret,omitempty"`
	}{AuthorizationRequest: request, ClientSecret: clientSecret}, &result); err != nil {
		return PushedRequest{}, err
	}
	return result, nil
}

// DeviceAuthorizationStart begins the device grant (RFC 8628). The device
// displays the returned user code; the person approves it elsewhere.
func (c *Client) DeviceAuthorizationStart(
	ctx context.Context,
	clientID string,
	scopes []string,
) (map[string]any, error) {
	var result map[string]any
	if err := c.Request(ctx, "oidc.device_authorize", map[string]any{
		"client_id": clientID, "scopes": scopes,
	}, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// DeviceAuthorizationLookup resolves a typed user code to the request a person
// is being asked to approve.
func (c *Client) DeviceAuthorizationLookup(
	ctx context.Context,
	tenantID, userCode string,
) (map[string]any, error) {
	var result map[string]any
	if err := c.Request(ctx, "oidc.device_lookup", map[string]any{
		"tenant_id": tenantID, "user_code": userCode,
	}, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// DeviceAuthorizationApprove binds an authenticated session to a waiting
// device. The session is proved rather than named.
func (c *Client) DeviceAuthorizationApprove(
	ctx context.Context,
	tenantID, userCode, sessionID, sessionSecret string,
) (map[string]any, error) {
	var result map[string]any
	if err := c.Request(ctx, "oidc.device_approve", map[string]any{
		"tenant_id": tenantID, "user_code": userCode,
		"session_id": sessionID, "session_secret": sessionSecret,
	}, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// DeviceAuthorizationDeny records a person refusing a device.
func (c *Client) DeviceAuthorizationDeny(
	ctx context.Context,
	tenantID, userCode string,
) (map[string]any, error) {
	var result map[string]any
	if err := c.Request(ctx, "oidc.device_deny", map[string]any{
		"tenant_id": tenantID, "user_code": userCode,
	}, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *Client) TokenExchange(ctx context.Context, request TokenRequest) (TokenResponse, error) {
	var result TokenResponse
	if err := c.Request(ctx, "oidc.token", request, &result); err != nil {
		return TokenResponse{}, err
	}
	return result, nil
}

// Passkey is one registered WebAuthn credential. It carries a public key and
// a sign counter; nothing private is ever stored or returned.
type Passkey struct {
	CredentialID string `json:"credential_id"`
	PrincipalID  string `json:"principal_id"`
	TenantID     string `json:"tenant_id"`
	PublicKey    string `json:"public_key"`
	SignCount    uint32 `json:"sign_count"`
	UserVerified bool   `json:"user_verified"`
	RegisteredAt string `json:"registered_at"`
}

// PasskeyRegistrationRequest is what a browser needs to create a credential.
// The challenge is engine-issued, single-use, and expires.
type PasskeyRegistrationRequest struct {
	PrincipalID    string `json:"principal_id"`
	Challenge      string `json:"challenge"`
	RelyingPartyID string `json:"relying_party_id"`
	Origin         string `json:"origin"`
	ExpiresAt      string `json:"expires_at"`
}

// PasskeyAuthenticationRequest is what a browser needs to produce an
// assertion for an in-flight authentication transaction.
type PasskeyAuthenticationRequest struct {
	TransactionID  string   `json:"transaction_id"`
	Challenge      string   `json:"challenge"`
	RelyingPartyID string   `json:"relying_party_id"`
	Origin         string   `json:"origin"`
	CredentialIDs  []string `json:"credential_ids"`
}

// PasskeyRegisterBegin issues a registration challenge.
func (c *Client) PasskeyRegisterBegin(ctx context.Context, principalID string) (PasskeyRegistrationRequest, error) {
	var result PasskeyRegistrationRequest
	if err := c.Request(ctx, "authenticator.passkey_register_begin",
		map[string]string{"principal_id": principalID}, &result); err != nil {
		return PasskeyRegistrationRequest{}, err
	}
	return result, nil
}

// PasskeyRegisterFinish verifies an attestation and stores the credential.
// Both arguments are the raw bytes the browser produced; the SDK base64-encodes
// them for transport.
func (c *Client) PasskeyRegisterFinish(
	ctx context.Context,
	principalID string,
	attestationObject, clientDataJSON []byte,
) (Passkey, error) {
	var result Passkey
	if err := c.Request(ctx, "authenticator.passkey_register_finish", map[string]string{
		"principal_id":       principalID,
		"attestation_object": base64.RawURLEncoding.EncodeToString(attestationObject),
		"client_data_json":   base64.RawURLEncoding.EncodeToString(clientDataJSON),
	}, &result); err != nil {
		return Passkey{}, err
	}
	return result, nil
}

// PasskeyList returns a principal's registered credentials.
func (c *Client) PasskeyList(ctx context.Context, principalID string) ([]Passkey, error) {
	var result struct {
		Passkeys []Passkey `json:"passkeys"`
	}
	if err := c.Request(ctx, "authenticator.passkey_list",
		map[string]string{"principal_id": principalID}, &result); err != nil {
		return nil, err
	}
	return result.Passkeys, nil
}

// PasskeyRemove durably unregisters a credential.
func (c *Client) PasskeyRemove(ctx context.Context, credentialID string) error {
	var result struct {
		Removed bool `json:"removed"`
	}
	return c.Request(ctx, "authenticator.passkey_remove",
		map[string]string{"credential_id": credentialID}, &result)
}

// PasskeyOptions returns what a browser needs to answer a passkey challenge
// for an in-flight transaction.
func (c *Client) PasskeyOptions(ctx context.Context, transactionID string) (PasskeyAuthenticationRequest, error) {
	var result PasskeyAuthenticationRequest
	if err := c.Request(ctx, "authn.passkey_options",
		map[string]string{"transaction_id": transactionID}, &result); err != nil {
		return PasskeyAuthenticationRequest{}, err
	}
	return result, nil
}

// AuthenticationVerifyPasskey advances a transaction with a passkey
// assertion. A passkey needs no prior factor, and a user-verified one
// establishes MFA on its own.
func (c *Client) AuthenticationVerifyPasskey(
	ctx context.Context,
	transactionID, credentialID string,
	authenticatorData, clientDataJSON, signature []byte,
) (AuthenticationResult, error) {
	var result AuthenticationResult
	if err := c.Request(ctx, "authn.verify_passkey", map[string]string{
		"transaction_id":     transactionID,
		"credential_id":      credentialID,
		"authenticator_data": base64.RawURLEncoding.EncodeToString(authenticatorData),
		"client_data_json":   base64.RawURLEncoding.EncodeToString(clientDataJSON),
		"signature":          base64.RawURLEncoding.EncodeToString(signature),
	}, &result); err != nil {
		return AuthenticationResult{}, err
	}
	return result, nil
}

// ProviderMetadata is the OpenID provider configuration.
type ProviderMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

// DiscoveryEndpoints are the host's own route paths. SESAME owns no listener,
// so the host says where its routes live; the engine composes them under the
// configured issuer and refuses any that would leave that origin. Empty
// fields take the conventional defaults.
type DiscoveryEndpoints struct {
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string `json:"token_endpoint,omitempty"`
	JWKSURI               string `json:"jwks_uri,omitempty"`
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint    string `json:"revocation_endpoint,omitempty"`
	EndSessionEndpoint    string `json:"end_session_endpoint,omitempty"`
}

// Discovery returns the provider configuration for the host to serve at its
// own /.well-known/openid-configuration.
func (c *Client) Discovery(ctx context.Context, endpoints DiscoveryEndpoints) (ProviderMetadata, error) {
	var result ProviderMetadata
	if err := c.Request(ctx, "oidc.discovery", endpoints, &result); err != nil {
		return ProviderMetadata{}, err
	}
	return result, nil
}

// Introspection is the RFC 7662 response. Every field other than Active is
// absent when the token is not active.
type Introspection struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  string `json:"aud,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	ID        string `json:"jti,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	SessionID string `json:"sid,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
}

// Introspect reports whether a token is currently usable.
//
// A verifying signature is not the same as a standing grant: an access token
// is a self-contained JWT SESAME cannot recall, so this is where a revoked
// session or suspended principal shows up. The calling client must
// authenticate and may only introspect its own tokens.
func (c *Client) Introspect(ctx context.Context, clientID, clientSecret, token string) (Introspection, error) {
	var result Introspection
	if err := c.Request(ctx, "oidc.introspect", map[string]string{
		"token":         token,
		"client_id":     clientID,
		"client_secret": clientSecret,
	}, &result); err != nil {
		return Introspection{}, err
	}
	return result, nil
}

// Revoke ends a refresh token's whole family. It acknowledges an unknown or
// unrecallable token identically, as RFC 7009 requires: an endpoint that
// distinguished them would confirm token guesses. An access token cannot be
// recalled — revoke the refresh family or the session behind it.
func (c *Client) Revoke(ctx context.Context, clientID, clientSecret, token string) error {
	var result struct {
		Acknowledged bool `json:"acknowledged"`
	}
	return c.Request(ctx, "oidc.revoke", map[string]string{
		"token":         token,
		"client_id":     clientID,
		"client_secret": clientSecret,
	}, &result)
}

// JWK is one published public signing key.
type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Curve     string `json:"crv"`
	X         string `json:"x"`
	Y         string `json:"y"`
}

// JWKS is the published key set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// SigningKeys returns the engine's public key set, for the host to serve at
// its own JWKS endpoint. It contains no private material.
func (c *Client) SigningKeys(ctx context.Context) (JWKS, error) {
	var result JWKS
	if err := c.Request(ctx, "token.jwks", struct{}{}, &result); err != nil {
		return JWKS{}, err
	}
	return result, nil
}

// Metrics is the stable system.metrics result. Counters are cumulative for
// the life of the child process.
type Metrics struct {
	UptimeSeconds     float64          `json:"uptime_seconds"`
	Goroutines        int              `json:"goroutines"`
	HeapAllocBytes    uint64           `json:"heap_alloc_bytes"`
	StorageConfigured bool             `json:"storage_configured"`
	RequestsTotal     map[string]int64 `json:"requests_total"`
	ErrorsTotal       map[string]int64 `json:"errors_total"`
}

// Metrics reports process counters for operators. It carries no identity or
// key material — only operation names and counts.
func (c *Client) Metrics(ctx context.Context) (Metrics, error) {
	var result Metrics
	if err := c.Request(ctx, "system.metrics", struct{}{}, &result); err != nil {
		return Metrics{}, err
	}
	return result, nil
}

// Readiness reports whether the child can safely execute security operations.
func (c *Client) Readiness(ctx context.Context) (string, string, error) {
	var status struct {
		Status     string `json:"status"`
		ReasonCode string `json:"reason_code"`
	}
	if err := c.Request(ctx, "system.readiness", struct{}{}, &status); err != nil {
		return "", "", err
	}
	return status.Status, status.ReasonCode, nil
}

// Request sends one operation and decodes its result into result.
func (c *Client) Request(ctx context.Context, operation string, parameters, result any) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return errors.New("sesame client is closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	requestID, err := newRequestID()
	if err != nil {
		return err
	}
	frame := request{
		ProtocolVersion: protocolVersion,
		RequestID:       requestID,
		Operation:       operation,
		Parameters:      parameters,
	}
	encoded, err := json.Marshal(frame)
	if err != nil {
		return fmt.Errorf("encode sesame request: %w", err)
	}
	if len(encoded) > maxFrameBytes {
		return errors.New("sesame request exceeds the maximum frame size")
	}
	encoded = append(encoded, '\n')
	if _, err := c.stdin.Write(encoded); err != nil {
		return fmt.Errorf("write sesame request: %w", err)
	}

	type scanResult struct {
		frame []byte
		err   error
	}
	scanned := make(chan scanResult, 1)
	go func() {
		if !c.stdout.Scan() {
			err := c.stdout.Err()
			if err == nil {
				err = io.EOF
			}
			scanned <- scanResult{err: err}
			return
		}
		frameCopy := append([]byte(nil), c.stdout.Bytes()...)
		scanned <- scanResult{frame: frameCopy}
	}()

	select {
	case <-ctx.Done():
		c.closed = true
		_ = c.command.Process.Kill()
		return ctx.Err()
	case scan := <-scanned:
		if scan.err != nil {
			return fmt.Errorf("read sesame response: %w", scan.err)
		}
		return decodeResponse(requestID, scan.frame, result)
	}
}

// Close asks the child process to exit and forcibly stops it if it does not.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true
	_ = c.stdin.Close()

	timer := time.NewTimer(closeTimeout)
	defer timer.Stop()

	select {
	case err := <-c.done:
		if err != nil {
			return fmt.Errorf("wait for sesame process: %w", err)
		}
		return nil
	case <-timer.C:
		if err := c.command.Process.Kill(); err != nil {
			return fmt.Errorf("kill unresponsive sesame process: %w", err)
		}
		<-c.done
		return errors.New("sesame process did not exit before the close timeout")
	}
}

func newRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate sesame request id: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func decodeResponse(requestID string, frame []byte, result any) error {
	if len(frame) > maxFrameBytes {
		return errors.New("sesame response exceeds the maximum frame size")
	}
	if !json.Valid(frame) {
		return errors.New("sesame response is not valid JSON")
	}
	if err := rejectDuplicateKeys(frame); err != nil {
		return fmt.Errorf("sesame response contains duplicate object fields: %w", err)
	}

	var response response
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return fmt.Errorf("decode sesame response: %w", err)
	}
	if response.ProtocolVersion != protocolVersion {
		return fmt.Errorf("unexpected sesame protocol version %q", response.ProtocolVersion)
	}
	if response.RequestID != requestID {
		return fmt.Errorf("sesame response request_id %q does not match %q", response.RequestID, requestID)
	}
	if !response.OK {
		if response.Error == nil {
			return errors.New("sesame returned an error without an error body")
		}
		return response.Error
	}
	if response.Error != nil {
		return errors.New("sesame returned both a result and an error")
	}
	if result == nil {
		return nil
	}
	if err := json.Unmarshal(response.Result, result); err != nil {
		return fmt.Errorf("decode sesame result: %w", err)
	}
	return nil
}

func rejectDuplicateKeys(frame []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
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
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

type request struct {
	ProtocolVersion string `json:"protocol_version"`
	RequestID       string `json:"request_id"`
	Operation       string `json:"operation"`
	Parameters      any    `json:"parameters"`
}

type response struct {
	ProtocolVersion string          `json:"protocol_version"`
	RequestID       string          `json:"request_id"`
	OK              bool            `json:"ok"`
	Result          json.RawMessage `json:"result"`
	Error           *ProtocolError  `json:"error"`
}

// Inbound OIDC federation. The engine performs no network I/O: register
// and configure return the exact URL the host must fetch, and every
// document the host brings back is validated in the engine as untrusted
// input.
func (c *Client) ProviderRegister(
	ctx context.Context,
	tenantID, name, issuer, clientID, clientSecret string,
	scopes []string,
	subjectClaim, emailClaim, linking string,
) (map[string]any, error) {
	var result map[string]any
	if err := c.Request(ctx, "federation.provider_register", map[string]any{
		"tenant_id":     tenantID,
		"name":          name,
		"issuer":        issuer,
		"client_id":     clientID,
		"client_secret": clientSecret,
		"scopes":        scopes,
		"subject_claim": subjectClaim,
		"email_claim":   emailClaim,
		"linking":       linking,
	}, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// SAMLProviderRegister registers an external SAML identity provider.
//
// Certificates are PEM or bare base64. Several is normal during a rotation:
// the provider publishes the new one before it starts signing with it.
func (c *Client) SAMLProviderRegister(
	ctx context.Context,
	tenantID, name, entityID, ssoURL string,
	certificates []string,
	identifierNamespace, linking string,
) (map[string]any, error) {
	var result map[string]any
	if err := c.Request(ctx, "saml.provider_register", map[string]any{
		"tenant_id":            tenantID,
		"name":                 name,
		"entity_id":            entityID,
		"sso_url":              ssoURL,
		"certificates":         certificates,
		"identifier_namespace": identifierNamespace,
		"linking":              linking,
	}, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *Client) SAMLProviderGet(ctx context.Context, tenantID, providerID string) (map[string]any, error) {
	var result map[string]any
	if err := c.Request(ctx, "saml.provider_get", map[string]any{
		"tenant_id": tenantID, "provider_id": providerID,
	}, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *Client) SAMLProviderDisable(ctx context.Context, tenantID, providerID, reason string) (map[string]any, error) {
	var result map[string]any
	if err := c.Request(ctx, "saml.provider_disable", map[string]any{
		"tenant_id": tenantID, "provider_id": providerID, "reason": reason,
	}, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *Client) SAMLLoginStart(ctx context.Context, tenantID, providerID, consumerURL string) (map[string]any, error) {
	var result map[string]any
	if err := c.Request(ctx, "saml.login_start", map[string]any{
		"tenant_id": tenantID, "provider_id": providerID, "consumer_url": consumerURL,
	}, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// SAMLLoginComplete hands the engine the base64 SAMLResponse exactly as the
// host received it. The host is never asked to have understood it.
func (c *Client) SAMLLoginComplete(ctx context.Context, tenantID, loginID, assertion string) (map[string]any, error) {
	var result map[string]any
	if err := c.Request(ctx, "saml.login_complete", map[string]any{
		"tenant_id": tenantID, "login_id": loginID, "assertion": assertion,
	}, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *Client) ProviderConfigure(
	ctx context.Context,
	tenantID, providerID, discoveryDocument, keySetDocument string,
) (map[string]any, error) {
	var result map[string]any
	if err := c.Request(ctx, "federation.provider_configure", map[string]any{
		"tenant_id":          tenantID,
		"provider_id":        providerID,
		"discovery_document": discoveryDocument,
		"key_set_document":   keySetDocument,
	}, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *Client) ProviderDisable(ctx context.Context, tenantID, providerID, reason string) (map[string]any, error) {
	var result map[string]any
	if err := c.Request(ctx, "federation.provider_disable", map[string]any{
		"tenant_id":   tenantID,
		"provider_id": providerID,
		"reason":      reason,
	}, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *Client) ProviderGet(ctx context.Context, tenantID, providerID string) (map[string]any, error) {
	var result map[string]any
	if err := c.Request(ctx, "federation.provider_get", map[string]any{
		"tenant_id":   tenantID,
		"provider_id": providerID,
	}, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *Client) FederatedLoginStart(
	ctx context.Context,
	tenantID, providerID, redirectURI string,
) (map[string]any, error) {
	var result map[string]any
	if err := c.Request(ctx, "federation.login_start", map[string]any{
		"tenant_id":    tenantID,
		"provider_id":  providerID,
		"redirect_uri": redirectURI,
	}, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *Client) FederatedLoginExchange(
	ctx context.Context,
	tenantID, loginID, state, code string,
) (map[string]any, error) {
	var result map[string]any
	if err := c.Request(ctx, "federation.login_exchange", map[string]any{
		"tenant_id": tenantID,
		"login_id":  loginID,
		"state":     state,
		"code":      code,
	}, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *Client) FederatedLoginComplete(
	ctx context.Context,
	tenantID, loginID, idToken string,
) (map[string]any, error) {
	var result map[string]any
	if err := c.Request(ctx, "federation.login_complete", map[string]any{
		"tenant_id": tenantID,
		"login_id":  loginID,
		"id_token":  idToken,
	}, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// SCIM 2.0 provisioning. Every resource operation carries the bearer token,
// so the engine always authenticates and a host cannot forget to.
func (c *Client) ProvisioningClientRegister(
	ctx context.Context,
	tenantID, name, identifierNamespace string,
	canManageGroups bool,
) (map[string]any, error) {
	return c.scimRequest(ctx, "scim.client_register", map[string]any{
		"tenant_id":            tenantID,
		"name":                 name,
		"identifier_namespace": identifierNamespace,
		"can_manage_groups":    canManageGroups,
	})
}

func (c *Client) ProvisioningClientDisable(
	ctx context.Context,
	tenantID, scimClientID, reason string,
) (map[string]any, error) {
	return c.scimRequest(ctx, "scim.client_disable", map[string]any{
		"tenant_id":      tenantID,
		"scim_client_id": scimClientID,
		"reason":         reason,
	})
}

func (c *Client) ProvisioningClientRotateToken(
	ctx context.Context,
	tenantID, scimClientID string,
) (map[string]any, error) {
	return c.scimRequest(ctx, "scim.client_rotate_token", map[string]any{
		"tenant_id":      tenantID,
		"scim_client_id": scimClientID,
	})
}

func (c *Client) SCIMUserCreate(ctx context.Context, token, body string) (map[string]any, error) {
	return c.scimRequest(ctx, "scim.user_create", map[string]any{
		"token": token,
		"body":  body,
	})
}

func (c *Client) SCIMUserGet(ctx context.Context, token, resourceID string) (map[string]any, error) {
	return c.scimRequest(ctx, "scim.user_get", map[string]any{
		"token":       token,
		"resource_id": resourceID,
	})
}

func (c *Client) SCIMUserList(
	ctx context.Context,
	token, filter string,
	startIndex, count int,
) (map[string]any, error) {
	return c.scimRequest(ctx, "scim.user_list", map[string]any{
		"token":       token,
		"filter":      filter,
		"start_index": startIndex,
		"count":       count,
	})
}

func (c *Client) SCIMUserPatch(
	ctx context.Context,
	token, resourceID, body string,
) (map[string]any, error) {
	return c.scimRequest(ctx, "scim.user_patch", map[string]any{
		"token":       token,
		"resource_id": resourceID,
		"body":        body,
	})
}

func (c *Client) SCIMUserDeprovision(
	ctx context.Context,
	token, resourceID string,
) (map[string]any, error) {
	return c.scimRequest(ctx, "scim.user_deprovision", map[string]any{
		"token":       token,
		"resource_id": resourceID,
	})
}

// scimRequest keeps the seven provisioning methods to one shape each.
func (c *Client) scimRequest(
	ctx context.Context,
	operation string,
	parameters map[string]any,
) (map[string]any, error) {
	var result map[string]any
	if err := c.Request(ctx, operation, parameters, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// SCIM Group provisioning. These require the provisioning client's
// can_manage_groups grant: group membership drives authorization decisions.
func (c *Client) SCIMGroupCreate(ctx context.Context, token, body string) (map[string]any, error) {
	return c.scimRequest(ctx, "scim.group_create", map[string]any{
		"token": token,
		"body":  body,
	})
}

func (c *Client) SCIMGroupGet(ctx context.Context, token, resourceID string) (map[string]any, error) {
	return c.scimRequest(ctx, "scim.group_get", map[string]any{
		"token":       token,
		"resource_id": resourceID,
	})
}

func (c *Client) SCIMGroupList(
	ctx context.Context,
	token, filter string,
	startIndex, count int,
) (map[string]any, error) {
	return c.scimRequest(ctx, "scim.group_list", map[string]any{
		"token":       token,
		"filter":      filter,
		"start_index": startIndex,
		"count":       count,
	})
}

func (c *Client) SCIMGroupPatch(
	ctx context.Context,
	token, resourceID, body string,
) (map[string]any, error) {
	return c.scimRequest(ctx, "scim.group_patch", map[string]any{
		"token":       token,
		"resource_id": resourceID,
		"body":        body,
	})
}

func (c *Client) SCIMGroupDeprovision(
	ctx context.Context,
	token, resourceID string,
) (map[string]any, error) {
	return c.scimRequest(ctx, "scim.group_deprovision", map[string]any{
		"token":       token,
		"resource_id": resourceID,
	})
}
