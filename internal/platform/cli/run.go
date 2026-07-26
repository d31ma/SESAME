// Package cli implements the SESAME operator command line.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	fyloadapter "github.com/d31ma/sesame/internal/adapters/fylo"
	"github.com/d31ma/sesame/internal/adapters/fylo/securityledger"
	"github.com/d31ma/sesame/internal/adapters/machine"
	"github.com/d31ma/sesame/internal/application/identity"
	"github.com/d31ma/sesame/internal/application/system"
	authzdomain "github.com/d31ma/sesame/internal/domain/authorization"
	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	sessiondomain "github.com/d31ma/sesame/internal/domain/session"
	tokendomain "github.com/d31ma/sesame/internal/domain/token"
	"github.com/d31ma/sesame/internal/platform/buildinfo"
	"github.com/d31ma/sesame/internal/platform/deployment"
)

const (
	// ExitSuccess indicates successful command completion.
	ExitSuccess = 0
	// ExitFailure indicates an operational failure.
	ExitFailure = 1
	// ExitUsage indicates invalid command syntax or arguments.
	ExitUsage = 2
)

// Run executes one CLI invocation and returns a process exit code.
func Run(
	ctx context.Context,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	info buildinfo.Info,
) int {
	if len(args) == 0 {
		writeUsage(stdout)
		return ExitSuccess
	}

	service := system.New(info)

	switch args[0] {
	case "help", "-h", "--help":
		writeUsage(stdout)
		return ExitSuccess
	case "version":
		return runVersion(args[1:], stdout, stderr, info)
	case "exec":
		return runExec(ctx, args[1:], stdin, stdout, stderr, service)
	case "tenant":
		return runTenant(ctx, args[1:], stdout, stderr)
	case "principal":
		return runPrincipal(ctx, args[1:], stdout, stderr)
	case "authn", "session":
		return runAuthentication(ctx, args[0], args[1:], stdout, stderr)
	case "token":
		return runToken(ctx, args[1:], stdout, stderr)
	case "client":
		return runClient(ctx, args[1:], stdout, stderr)
	case "federation":
		return runFederation(ctx, args[1:], stdout, stderr)
	case "provisioning":
		return runProvisioning(ctx, args[1:], stdout, stderr)
	case "saml":
		return runSAML(ctx, args[1:], stdout, stderr)
	case "device":
		return runDevice(ctx, args[1:], stdout, stderr)
	case "role", "grant", "authorize", "group", "admin":
		return runAuthorization(ctx, args[0], args[1:], stdout, stderr)
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "sesame: unknown command %q\n\n", args[0])
		writeUsage(stderr)
		return ExitUsage
	}
}

func runVersion(args []string, stdout, stderr io.Writer, info buildinfo.Info) int {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("output", "text", "output format: text or json")
	if err := flags.Parse(args); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "sesame version: unexpected positional arguments")
		return ExitUsage
	}

	switch *output {
	case "text":
		_, _ = fmt.Fprintf(
			stdout,
			"%s %s (commit %s, built %s, %s, %s/%s)\n",
			info.Name,
			info.Version,
			info.Commit,
			info.BuiltAt,
			info.GoVersion,
			info.OS,
			info.Arch,
		)
	case "json":
		if err := json.NewEncoder(stdout).Encode(info); err != nil {
			_, _ = fmt.Fprintf(stderr, "sesame version: encode output: %v\n", err)
			return ExitFailure
		}
	default:
		_, _ = fmt.Fprintf(stderr, "sesame version: unsupported output format %q\n", *output)
		return ExitUsage
	}

	return ExitSuccess
}

func runExec(
	ctx context.Context,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	service *system.Service,
) int {
	flags := flag.NewFlagSet("exec", flag.ContinueOnError)
	flags.SetOutput(stderr)
	loop := flags.Bool("loop", false, "process newline-delimited machine requests until EOF")
	storage := addStorageFlags(flags)
	if err := flags.Parse(args); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 || !*loop {
		_, _ = fmt.Fprintln(stderr, "usage: sesame exec --loop [--deployment DIR | --fylo-binary PATH --fylo-root PATH]")
		return ExitUsage
	}

	logger := newLogger(stderr)
	tenantService, closeStorage, err := openStorage(ctx, logger, *storage)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame exec: %v\n", err)
		return ExitFailure
	}
	defer closeStorage()
	if tenantService != nil {
		service.MarkStorageReady()
	}

	logger.Info("machine loop started", "storage_configured", tenantService != nil)
	processor := machine.New(service, tenantService)
	processor.UseTracer(logger)
	if err := processor.Run(ctx, stdin, stdout); err != nil {
		logger.Error("machine loop failed", "error", err.Error())
		_, _ = fmt.Fprintf(stderr, "sesame exec: %v\n", err)
		return ExitFailure
	}
	logger.Info("machine loop stopped")
	return ExitSuccess
}

// newLogger writes structured JSON diagnostics to stderr; machine stdout
// carries only protocol frames.
func newLogger(stderr io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(stderr, nil))
}

// storageOptions selects the FYLO boundary: a deployment directory or an
// explicit binary/root pair without snapshots.
type storageOptions struct {
	Deployment string
	FYLOBinary string
	FYLORoot   string
}

func addStorageFlags(flags *flag.FlagSet) *storageOptions {
	options := &storageOptions{}
	flags.StringVar(&options.Deployment, "deployment", "",
		"deployment directory created by sesame init (default "+EnvDeployment+")")
	flags.StringVar(&options.FYLOBinary, "fylo-binary", "",
		"absolute path to the pinned FYLO executable (default "+EnvFYLOBinary+")")
	flags.StringVar(&options.FYLORoot, "fylo-root", "",
		"absolute path to the exclusively owned FYLO data root (default "+EnvFYLORoot+")")
	return options
}

// Environment variables that stand in for the storage flags, so a deployed
// application can be configured once by its process environment rather than
// by every call site.
//
// The two FYLO settings keep FYLO's own names rather than taking a SESAME_
// prefix. SESAME runs FYLO as a child that inherits this environment and
// reads FYLO_ROOT itself, so one variable configures both sides; inventing
// SESAME_FYLO_ROOT beside it would mean two names for one value and a way for
// them to disagree. The deployment and the engine binary are SESAME's own
// concepts and have no FYLO equivalent, so they keep the prefix.
const (
	EnvDeployment = "SESAME_DEPLOYMENT"
	EnvFYLOBinary = "FYLO_BINARY"
	EnvFYLORoot   = "FYLO_ROOT"
)

// fromEnvironment fills unset options from the environment.
//
// An explicit flag always wins. That ordering matters more than it looks: an
// operator debugging a deployment on a host that already exports
// SESAME_DEPLOYMENT must be able to point one command somewhere else without
// unsetting anything, and silently preferring the environment would make the
// flag they just typed a lie.
//
// The result is a copy, so this is idempotent and safe to call more than once.
func (o storageOptions) fromEnvironment() storageOptions {
	// An explicit choice of one mode suppresses the other mode's variables.
	//
	// The deployment directory and the bare binary/root pair are alternatives,
	// and presenting both is refused. Without this, a host application that
	// passes --deployment breaks on any machine whose environment happens to
	// export FYLO_BINARY — a conflict between something it asked for and
	// something it never asked about. The caller has already chosen; the
	// environment only fills what was left open.
	chosenDeployment := o.Deployment != ""
	chosenBare := o.FYLOBinary != "" || o.FYLORoot != ""

	if !chosenBare {
		if o.Deployment == "" {
			o.Deployment = os.Getenv(EnvDeployment)
		}
	}
	if !chosenDeployment {
		if o.FYLOBinary == "" {
			o.FYLOBinary = os.Getenv(EnvFYLOBinary)
		}
		if o.FYLORoot == "" {
			// Only when set. FYLO defaults FYLO_ROOT to ./.fylo-data, which is
			// a reasonable default for a document store invoked ad hoc and a
			// bad one for an identity engine: SESAME would silently create a
			// store in whatever directory it happened to start in. An unset
			// root stays unset, and the binary/root pair is still required
			// together.
			o.FYLORoot = os.Getenv(EnvFYLORoot)
		}
	}
	return o
}

// orEnvironment falls back to a named variable, keeping the flag ahead of it.
func orEnvironment(value, variable string) string {
	if value != "" {
		return value
	}
	return os.Getenv(variable)
}

func (o storageOptions) configured() bool {
	resolved := o.fromEnvironment()
	return resolved.Deployment != "" || resolved.FYLOBinary != "" || resolved.FYLORoot != ""
}

// openStorage starts and verifies the FYLO boundary. A deployment directory
// enables verified snapshots; the bare binary/root pair replays the complete
// ledger. Both-or-neither on the pair keeps a half-configured deployment from
// silently running without durable storage.
func openStorage(
	ctx context.Context,
	logger *slog.Logger,
	options storageOptions,
) (*identity.Service, func(), error) {
	options = options.fromEnvironment()
	if !options.configured() {
		return nil, func() {}, nil
	}
	if options.Deployment != "" && (options.FYLOBinary != "" || options.FYLORoot != "") {
		return nil, nil, errors.New("--deployment (or " + EnvDeployment + ") cannot be combined with " +
			"--fylo-binary/--fylo-root (or " + EnvFYLOBinary + "/" + EnvFYLORoot + ")")
	}

	binary := options.FYLOBinary
	root := options.FYLORoot
	var snapshotKey []byte
	var secretsKey []byte
	var signingKey *tokendomain.SigningKey
	var issuer string
	fyloConfig := fyloadapter.Config{}
	if options.Deployment != "" {
		loaded, err := deployment.Load(options.Deployment)
		if err != nil {
			return nil, nil, err
		}
		binary = loaded.Config.FYLOBinary
		root = loaded.FYLORoot
		snapshotKey = loaded.SnapshotKey
		secretsKey = loaded.SecretsKey
		signingKey = loaded.SigningKey
		issuer = loaded.Config.Issuer
	} else if binary == "" || root == "" {
		return nil, nil, fmt.Errorf("--fylo-binary and --fylo-root (or %s and %s) must be provided together",
			EnvFYLOBinary, EnvFYLORoot)
	}

	fyloConfig.Binary = binary
	fyloConfig.Root = root
	client, err := fyloadapter.Start(ctx, fyloConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("start FYLO runtime: %w", err)
	}
	runtimeIdentity := client.Identity()
	logger.Info("storage connected",
		"runtime_version", runtimeIdentity.RuntimeVersion,
		"build_kind", runtimeIdentity.BuildKind,
		"commit", runtimeIdentity.Commit,
	)

	ledger, replayed, err := securityledger.OpenVerified(ctx, client, snapshotKey)
	if err != nil {
		_ = client.Close()
		return nil, nil, err
	}
	tenantService, err := identity.NewFromSnapshot(ledger, replayed.SnapshotState, replayed.TailEvents)
	if err != nil {
		_ = client.Close()
		return nil, nil, err
	}
	tenantService.UseLogger(logger)
	tenantService.UseSecretsKey(secretsKey)
	tenantService.UseSigningKey(signingKey)
	tenantService.UseIssuer(issuer)
	if len(snapshotKey) != 0 {
		tenantService.UseSnapshots(ledger)
	}
	logger.Info("security ledger replayed",
		"tail_events", len(replayed.TailEvents),
		"snapshot_used", replayed.SnapshotState != nil,
		"snapshot_sequence", replayed.SnapshotSequence,
	)
	return tenantService, func() { _ = client.Close() }, nil
}

func runInit(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("deployment", "",
		"deployment directory to create (default "+EnvDeployment+")")
	fyloBinary := flags.String("fylo-binary", "",
		"absolute path to the pinned FYLO executable (default "+EnvFYLOBinary+")")
	issuer := flags.String("issuer", "", "https base URL tokens are issued under, for example https://id.example")
	if err := flags.Parse(args); err != nil {
		return ExitUsage
	}
	// init reads the same environment every other command does. An operator
	// who has exported SESAME_DEPLOYMENT should not have to repeat it here of
	// all places — this is the command that decides what the others will find.
	//
	// Each value is resolved on its own rather than through the storage
	// options' mode selection: for init the deployment and the FYLO binary are
	// both required together, so the exclusivity that governs a running engine
	// would be exactly backwards here.
	deploymentDir := orEnvironment(*dir, EnvDeployment)
	runtimeBinary := orEnvironment(*fyloBinary, EnvFYLOBinary)
	if flags.NArg() != 0 || deploymentDir == "" || runtimeBinary == "" {
		_, _ = fmt.Fprintln(stderr,
			"usage: sesame init [--deployment DIR] [--fylo-binary PATH] [--issuer URL]\n"+
				"       "+EnvDeployment+" and "+EnvFYLOBinary+" supply either flag when it is omitted")
		return ExitUsage
	}

	created, err := deployment.Init(deploymentDir, runtimeBinary, *issuer)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame init: %v\n", err)
		return ExitFailure
	}
	// The summary never includes key material.
	summary := map[string]any{
		"deployment":     created.Dir,
		"config_version": created.Config.ConfigVersion,
		"fylo_binary":    created.Config.FYLOBinary,
		"fylo_root":      created.FYLORoot,
		"issuer":         created.Config.Issuer,
		// The key identifier is public: it is what a verifier matches a
		// token header against.
		"signing_key_id": created.SigningKey.ID,
	}
	if err := json.NewEncoder(stdout).Encode(summary); err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame init: encode output: %v\n", err)
		return ExitFailure
	}
	return ExitSuccess
}

// doctorReport is the stable sesame doctor output.
type doctorReport struct {
	Status        string   `json:"status"`
	Deployment    string   `json:"deployment"`
	ConfigVersion int      `json:"config_version,omitempty"`
	Issuer        string   `json:"issuer,omitempty"`
	SigningKeyID  string   `json:"signing_key_id,omitempty"`
	FYLO          any      `json:"fylo,omitempty"`
	Ledger        any      `json:"ledger,omitempty"`
	Failures      []string `json:"failures,omitempty"`
}

func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("deployment", "",
		"deployment directory to check (default "+EnvDeployment+")")
	if err := flags.Parse(args); err != nil {
		return ExitUsage
	}
	deploymentDir := orEnvironment(*dir, EnvDeployment)
	if flags.NArg() != 0 || deploymentDir == "" {
		_, _ = fmt.Fprintln(stderr, "usage: sesame doctor [--deployment DIR]\n"+
			"       "+EnvDeployment+" supplies the directory when the flag is omitted")
		return ExitUsage
	}

	report := diagnose(ctx, deploymentDir)
	if err := json.NewEncoder(stdout).Encode(report); err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame doctor: encode output: %v\n", err)
		return ExitFailure
	}
	if report.Status != "ok" {
		return ExitFailure
	}
	return ExitSuccess
}

func diagnose(ctx context.Context, dir string) doctorReport {
	report := doctorReport{Status: "failed", Deployment: dir}

	loaded, err := deployment.Load(dir)
	if err != nil {
		report.Failures = append(report.Failures, err.Error())
		return report
	}
	report.ConfigVersion = loaded.Config.ConfigVersion
	report.Issuer = loaded.Config.Issuer
	report.SigningKeyID = loaded.SigningKey.ID

	client, err := fyloadapter.Start(ctx, fyloadapter.Config{
		Binary: loaded.Config.FYLOBinary,
		Root:   loaded.FYLORoot,
	})
	if err != nil {
		report.Failures = append(report.Failures, fmt.Sprintf("start FYLO runtime: %v", err))
		return report
	}
	defer func() { _ = client.Close() }()
	runtimeIdentity := client.Identity()
	report.FYLO = map[string]any{
		"runtime_version": runtimeIdentity.RuntimeVersion,
		"protocol":        runtimeIdentity.ProtocolVersion,
		"commit":          runtimeIdentity.Commit,
		"build_kind":      runtimeIdentity.BuildKind,
		"build_target":    runtimeIdentity.BuildTarget,
	}

	// Snapshot-seeded state and complete replay must agree exactly.
	_, verified, err := securityledger.OpenVerified(ctx, client, loaded.SnapshotKey)
	if err != nil {
		report.Failures = append(report.Failures, err.Error())
		return report
	}
	snapshotService, err := identity.NewFromSnapshot(nil, verified.SnapshotState, verified.TailEvents)
	if err != nil {
		report.Failures = append(report.Failures, fmt.Sprintf("snapshot projection: %v", err))
		return report
	}
	_, full, err := securityledger.OpenVerified(ctx, client, nil)
	if err != nil {
		report.Failures = append(report.Failures, fmt.Sprintf("full replay: %v", err))
		return report
	}
	fullService, err := identity.NewFromSnapshot(nil, nil, full.TailEvents)
	if err != nil {
		report.Failures = append(report.Failures, fmt.Sprintf("full projection: %v", err))
		return report
	}
	snapshotState, err := json.Marshal(snapshotService.ExportState())
	if err != nil {
		report.Failures = append(report.Failures, fmt.Sprintf("encode snapshot state: %v", err))
		return report
	}
	fullState, err := json.Marshal(fullService.ExportState())
	if err != nil {
		report.Failures = append(report.Failures, fmt.Sprintf("encode full state: %v", err))
		return report
	}
	equivalent := string(snapshotState) == string(fullState)
	report.Ledger = map[string]any{
		"events_total":           len(full.TailEvents),
		"tail_events":            len(verified.TailEvents),
		"snapshot_used":          verified.SnapshotState != nil,
		"snapshot_sequence":      verified.SnapshotSequence,
		"snapshots_stored":       verified.SnapshotsStored,
		"full_replay_equivalent": equivalent,
	}
	if !equivalent {
		report.Failures = append(report.Failures, "snapshot-seeded state differs from complete replay")
		return report
	}

	report.Status = "ok"
	return report
}

func runTenant(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: sesame tenant bootstrap|get [flags]")
		return ExitUsage
	}
	subcommand := args[0]
	if subcommand != "bootstrap" && subcommand != "get" {
		_, _ = fmt.Fprintf(stderr, "sesame tenant: unknown subcommand %q\n", subcommand)
		return ExitUsage
	}

	flags := flag.NewFlagSet("tenant "+subcommand, flag.ContinueOnError)
	flags.SetOutput(stderr)
	storage := addStorageFlags(flags)
	name := flags.String("name", "", "tenant name")
	tenantID := flags.String("tenant-id", "", "tenant public identifier (get only)")
	if err := flags.Parse(args[1:]); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "sesame tenant %s: unexpected positional arguments\n", subcommand)
		return ExitUsage
	}
	if !storage.configured() {
		_, _ = fmt.Fprintf(stderr, "sesame tenant %s: --deployment or --fylo-binary/--fylo-root is required\n", subcommand)
		return ExitUsage
	}

	tenantService, closeStorage, err := openStorage(ctx, newLogger(stderr), *storage)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame tenant %s: %v\n", subcommand, err)
		return ExitFailure
	}
	defer closeStorage()

	var result any
	switch subcommand {
	case "bootstrap":
		if *tenantID != "" {
			_, _ = fmt.Fprintln(stderr, "sesame tenant bootstrap: --tenant-id is not accepted")
			return ExitUsage
		}
		result, err = tenantService.Bootstrap(ctx, *name, "operator:cli")
	case "get":
		switch {
		case (*name == "") == (*tenantID == ""):
			_, _ = fmt.Fprintln(stderr, "sesame tenant get: exactly one of --name or --tenant-id is required")
			return ExitUsage
		case *name != "":
			result, err = tenantService.GetByName(*name)
		default:
			result, err = tenantService.GetByID(*tenantID)
		}
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame tenant %s: %v\n", subcommand, err)
		return ExitFailure
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame tenant %s: encode output: %v\n", subcommand, err)
		return ExitFailure
	}
	return ExitSuccess
}

func runPrincipal(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: sesame principal create|get|suspend [flags]")
		return ExitUsage
	}
	subcommand := args[0]
	if subcommand != "create" && subcommand != "get" && subcommand != "suspend" {
		_, _ = fmt.Fprintf(stderr, "sesame principal: unknown subcommand %q\n", subcommand)
		return ExitUsage
	}

	flags := flag.NewFlagSet("principal "+subcommand, flag.ContinueOnError)
	flags.SetOutput(stderr)
	storage := addStorageFlags(flags)
	tenantID := flags.String("tenant-id", "", "owning tenant public identifier")
	kind := flags.String("kind", "", "principal kind: human or workload (create only)")
	namespace := flags.String("identifier-namespace", "", "identifier namespace, for example email or login")
	value := flags.String("identifier-value", "", "identifier value")
	principalID := flags.String("principal-id", "", "principal public identifier")
	if err := flags.Parse(args[1:]); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "sesame principal %s: unexpected positional arguments\n", subcommand)
		return ExitUsage
	}
	if !storage.configured() {
		_, _ = fmt.Fprintf(stderr, "sesame principal %s: --deployment or --fylo-binary/--fylo-root is required\n", subcommand)
		return ExitUsage
	}

	identityService, closeStorage, err := openStorage(ctx, newLogger(stderr), *storage)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame principal %s: %v\n", subcommand, err)
		return ExitFailure
	}
	defer closeStorage()

	var result any
	switch subcommand {
	case "create":
		result, err = identityService.PrincipalCreate(ctx, *tenantID, *kind, principaldomain.Identifier{
			Namespace: *namespace,
			Value:     *value,
		}, "operator:cli")
	case "get":
		byID := *principalID != ""
		byIdentifier := *tenantID != "" && *namespace != "" && *value != ""
		if byID == byIdentifier {
			_, _ = fmt.Fprintln(stderr, "sesame principal get: provide --principal-id or --tenant-id with --identifier-namespace and --identifier-value")
			return ExitUsage
		}
		if byID {
			result, err = identityService.PrincipalGetByID(*principalID)
		} else {
			result, err = identityService.PrincipalGetByIdentifier(*tenantID, principaldomain.Identifier{
				Namespace: *namespace,
				Value:     *value,
			})
		}
	case "suspend":
		result, err = identityService.PrincipalSuspend(ctx, *principalID, "operator:cli")
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame principal %s: %v\n", subcommand, err)
		return ExitFailure
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame principal %s: encode output: %v\n", subcommand, err)
		return ExitFailure
	}
	return ExitSuccess
}

// runAuthorization handles the role, grant, and authorize command families,
// which share storage flags and JSON output.
func runAuthorization(
	ctx context.Context,
	family string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	usage := map[string][]string{
		"role":      {"create"},
		"grant":     {"create", "revoke"},
		"authorize": {"decide"},
		"group":     {"create", "member-add", "member-remove"},
		"admin":     {"bootstrap"},
	}
	if len(args) == 0 || !contains(usage[family], args[0]) {
		_, _ = fmt.Fprintf(stderr, "usage: sesame %s %s [flags]\n", family, strings.Join(usage[family], "|"))
		return ExitUsage
	}
	subcommand := args[0]

	flags := flag.NewFlagSet(family+" "+subcommand, flag.ContinueOnError)
	flags.SetOutput(stderr)
	storage := addStorageFlags(flags)
	tenantID := flags.String("tenant-id", "", "tenant public identifier")
	name := flags.String("name", "", "role name (role create)")
	permissionList := flags.String("permissions", "", "comma-separated action=resource permission pairs (role create)")
	principalID := flags.String("principal-id", "", "principal public identifier")
	roleID := flags.String("role-id", "", "role public identifier")
	grantID := flags.String("grant-id", "", "grant public identifier (grant revoke)")
	groupID := flags.String("group-id", "", "group public identifier")
	namespace := flags.String("identifier-namespace", "", "administrator identifier namespace (admin bootstrap)")
	value := flags.String("identifier-value", "", "administrator identifier value (admin bootstrap)")
	action := flags.String("action", "", "concrete action (authorize decide)")
	resource := flags.String("resource", "", "concrete resource (authorize decide)")
	policyVersion := flags.Int64("policy-version", -1, "pin the decision to this policy version (authorize decide)")
	if err := flags.Parse(args[1:]); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "sesame %s %s: unexpected positional arguments\n", family, subcommand)
		return ExitUsage
	}
	if !storage.configured() {
		_, _ = fmt.Fprintf(stderr, "sesame %s %s: --deployment or --fylo-binary/--fylo-root is required\n", family, subcommand)
		return ExitUsage
	}

	identityService, closeStorage, err := openStorage(ctx, newLogger(stderr), *storage)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame %s %s: %v\n", family, subcommand, err)
		return ExitFailure
	}
	defer closeStorage()

	var result any
	switch family + " " + subcommand {
	case "role create":
		permissions, parseErr := parsePermissions(*permissionList)
		if parseErr != nil {
			_, _ = fmt.Fprintf(stderr, "sesame role create: %v\n", parseErr)
			return ExitUsage
		}
		result, err = identityService.RoleCreate(ctx, *tenantID, *name, permissions, "operator:cli")
	case "grant create":
		if (*principalID == "") == (*groupID == "") {
			_, _ = fmt.Fprintln(stderr, "sesame grant create: exactly one of --principal-id or --group-id is required")
			return ExitUsage
		}
		if *principalID != "" {
			result, err = identityService.GrantCreate(ctx, *tenantID, *principalID, *roleID, "operator:cli")
		} else {
			result, err = identityService.GrantCreateForGroup(ctx, *tenantID, *groupID, *roleID, "operator:cli")
		}
	case "group create":
		result, err = identityService.GroupCreate(ctx, *tenantID, *name, "operator:cli")
	case "group member-add":
		err = identityService.GroupMemberAdd(ctx, *groupID, *principalID, "operator:cli")
		result = map[string]any{"member": err == nil}
	case "group member-remove":
		err = identityService.GroupMemberRemove(ctx, *groupID, *principalID, "operator:cli")
		result = map[string]any{"member": false}
	case "admin bootstrap":
		result, err = identityService.AdminBootstrap(ctx, *name, principaldomain.Identifier{
			Namespace: *namespace,
			Value:     *value,
		}, "operator:cli")
	case "grant revoke":
		err = identityService.GrantRevoke(ctx, *grantID, "operator:cli")
		result = map[string]any{"revoked": err == nil}
	case "authorize decide":
		var pinned *int64
		if *policyVersion >= 0 {
			pinned = policyVersion
		}
		result, err = identityService.Decide(identity.DecisionRequest{
			TenantID:    *tenantID,
			PrincipalID: *principalID,
			Action:      *action,
			Resource:    *resource,
		}, pinned)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame %s %s: %v\n", family, subcommand, err)
		return ExitFailure
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame %s %s: encode output: %v\n", family, subcommand, err)
		return ExitFailure
	}
	return ExitSuccess
}

// parsePermissions decodes "action=resource,action=resource" pairs.
func parsePermissions(list string) ([]authzdomain.Permission, error) {
	if list == "" {
		return nil, errors.New("--permissions is required, for example doc:read=project:*")
	}
	var permissions []authzdomain.Permission
	for _, pair := range strings.Split(list, ",") {
		action, resource, found := strings.Cut(pair, "=")
		if !found || action == "" || resource == "" {
			return nil, fmt.Errorf("permission %q must be action=resource", pair)
		}
		permissions = append(permissions, authzdomain.Permission{Action: action, Resource: resource})
	}
	return permissions, nil
}

// splitList decodes a comma-separated flag. Empty entries are dropped so a
// trailing comma is not read as an empty redirect URI or scope, both of which
// the domain would reject anyway.
func splitList(list string) []string {
	var values []string
	for _, value := range strings.Split(list, ",") {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// runToken handles the token command family: publishing the public key set
// and killing a rotating refresh family. Only public key material is ever
// printed — the private half stays in the deployment key directory — and no
// command reads a token back, because none can.
func runToken(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	subcommands := []string{"jwks", "discovery", "revoke-family", "family"}
	if len(args) == 0 || !contains(subcommands, args[0]) {
		_, _ = fmt.Fprintf(stderr, "usage: sesame token %s [flags]\n", strings.Join(subcommands, "|"))
		return ExitUsage
	}
	subcommand := args[0]

	flags := flag.NewFlagSet("token "+subcommand, flag.ContinueOnError)
	flags.SetOutput(stderr)
	storage := addStorageFlags(flags)
	familyID := flags.String("family-id", "", "refresh token family identifier")
	reason := flags.String("reason", "", "reason recorded with a revocation")
	authorizeEndpoint := flags.String("authorize-endpoint", "", "host path for the authorization endpoint")
	tokenEndpoint := flags.String("token-endpoint", "", "host path for the token endpoint")
	jwksEndpoint := flags.String("jwks-uri", "", "host path for the JWKS endpoint")
	if err := flags.Parse(args[1:]); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "sesame token %s: unexpected positional arguments\n", subcommand)
		return ExitUsage
	}
	if !storage.configured() {
		_, _ = fmt.Fprintf(stderr, "sesame token %s: --deployment or --fylo-binary/--fylo-root is required\n", subcommand)
		return ExitUsage
	}

	identityService, closeStorage, err := openStorage(ctx, newLogger(stderr), *storage)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame token %s: %v\n", subcommand, err)
		return ExitFailure
	}
	defer closeStorage()

	var result any
	switch subcommand {
	case "jwks":
		result, err = identityService.SigningKeys()
	case "discovery":
		// Endpoint paths default to the conventional ones; a host that
		// mounts its routes elsewhere passes its own.
		result, err = identityService.Discovery(oidcdomain.Endpoints{
			Authorization: *authorizeEndpoint,
			Token:         *tokenEndpoint,
			JWKS:          *jwksEndpoint,
		})
	case "revoke-family":
		err = identityService.RefreshFamilyRevoke(ctx, *familyID, *reason, "operator:cli")
		result = map[string]bool{"revoked": err == nil}
	case "family":
		result, err = identityService.RefreshFamilyGet(*familyID)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame token %s: %v\n", subcommand, err)
		return ExitFailure
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame token %s: encode output: %v\n", subcommand, err)
		return ExitFailure
	}
	return ExitSuccess
}

// runClient handles OIDC relying-party administration.
//
// register and rotate-secret print a secret that is never recoverable
// afterwards; there is no command that reads one back, because none can be.
func runClient(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	subcommands := []string{"register", "get", "rotate-secret", "disable", "consent", "withdraw-consent"}
	if len(args) == 0 || !contains(subcommands, args[0]) {
		_, _ = fmt.Fprintf(stderr, "usage: sesame client %s [flags]\n", strings.Join(subcommands, "|"))
		return ExitUsage
	}
	subcommand := args[0]

	flags := flag.NewFlagSet("client "+subcommand, flag.ContinueOnError)
	flags.SetOutput(stderr)
	storage := addStorageFlags(flags)
	tenantID := flags.String("tenant-id", "", "tenant public identifier")
	clientID := flags.String("client-id", "", "client public identifier")
	principalID := flags.String("principal-id", "", "principal public identifier")
	name := flags.String("name", "", "client display name")
	clientType := flags.String("type", "confidential", "client type: confidential or public")
	audience := flags.String("audience", "third_party",
		"first_party skips user consent; third_party requires it")
	postLogoutURIs := flags.String("post-logout-redirect-uris", "",
		"comma-separated exact URIs a logout may return to")
	redirectURIs := flags.String("redirect-uris", "", "comma-separated exact redirect URIs")
	scopes := flags.String("scopes", "", "comma-separated scopes; openid is always included")
	reason := flags.String("reason", "", "reason recorded with a disable")
	if err := flags.Parse(args[1:]); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "sesame client %s: unexpected positional arguments\n", subcommand)
		return ExitUsage
	}
	if !storage.configured() {
		_, _ = fmt.Fprintf(stderr, "sesame client %s: --deployment or --fylo-binary/--fylo-root is required\n", subcommand)
		return ExitUsage
	}

	identityService, closeStorage, err := openStorage(ctx, newLogger(stderr), *storage)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame client %s: %v\n", subcommand, err)
		return ExitFailure
	}
	defer closeStorage()

	var result any
	switch subcommand {
	case "register":
		result, err = identityService.ClientRegister(ctx, *tenantID, *name, *clientType,
			splitList(*redirectURIs), splitList(*scopes), *audience,
			splitList(*postLogoutURIs), "operator:cli")
	case "get":
		result, err = identityService.ClientGet(*clientID)
	case "rotate-secret":
		var secret string
		secret, err = identityService.ClientRotateSecret(ctx, *clientID, "operator:cli")
		result = map[string]string{"client_secret": secret}
	case "disable":
		err = identityService.ClientDisable(ctx, *clientID, *reason, "operator:cli")
		result = map[string]bool{"disabled": err == nil}
	case "consent":
		result, err = identityService.ConsentGet(*principalID, *clientID)
	case "withdraw-consent":
		// Withdrawing also revokes every refresh family this client holds
		// for the principal, so the client stops minting tokens too.
		err = identityService.ConsentWithdraw(ctx, *principalID, *clientID, "operator:cli")
		result = map[string]bool{"withdrawn": err == nil}
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame client %s: %v\n", subcommand, err)
		return ExitFailure
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame client %s: encode output: %v\n", subcommand, err)
		return ExitFailure
	}
	return ExitSuccess
}

// runAuthentication handles the authn and session command families.
//
// Credentials are read from environment variables rather than flags so they
// do not land in shell history or a process listing.
func runAuthentication(
	ctx context.Context,
	family string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	usage := map[string][]string{
		"authn":   {"set-password", "login", "totp-enroll", "totp-activate", "passkey-list", "passkey-remove"},
		"session": {"verify", "revoke"},
	}
	if len(args) == 0 || !contains(usage[family], args[0]) {
		_, _ = fmt.Fprintf(stderr, "usage: sesame %s %s [flags]\n", family, strings.Join(usage[family], "|"))
		return ExitUsage
	}
	subcommand := args[0]

	flags := flag.NewFlagSet(family+" "+subcommand, flag.ContinueOnError)
	flags.SetOutput(stderr)
	storage := addStorageFlags(flags)
	tenantID := flags.String("tenant-id", "", "tenant public identifier")
	principalID := flags.String("principal-id", "", "principal public identifier")
	namespace := flags.String("identifier-namespace", "", "identifier namespace")
	value := flags.String("identifier-value", "", "identifier value")
	sessionID := flags.String("session-id", "", "session public identifier")
	reason := flags.String("reason", "", "revocation reason")
	lifetime := flags.Duration("lifetime", 0, "session lifetime, for example 1h")
	passwordVar := flags.String("password-env", "SESAME_PASSWORD",
		"environment variable holding the password")
	secretVar := flags.String("session-secret-env", "SESAME_SESSION_SECRET",
		"environment variable holding the session secret")
	code := flags.String("code", "", "TOTP code")
	totpVar := flags.String("totp-code-env", "SESAME_TOTP_CODE",
		"environment variable holding a TOTP code for login")
	issuer := flags.String("issuer", "SESAME", "issuer shown in the authenticator app")
	credentialID := flags.String("credential-id", "", "passkey credential identifier")
	if err := flags.Parse(args[1:]); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "sesame %s %s: unexpected positional arguments\n", family, subcommand)
		return ExitUsage
	}
	if !storage.configured() {
		_, _ = fmt.Fprintf(stderr, "sesame %s %s: --deployment or --fylo-binary/--fylo-root is required\n", family, subcommand)
		return ExitUsage
	}

	identityService, closeStorage, err := openStorage(ctx, newLogger(stderr), *storage)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame %s %s: %v\n", family, subcommand, err)
		return ExitFailure
	}
	defer closeStorage()

	var result any
	switch family + " " + subcommand {
	case "authn set-password":
		password := os.Getenv(*passwordVar)
		if password == "" {
			_, _ = fmt.Fprintf(stderr, "sesame authn set-password: set the password in $%s\n", *passwordVar)
			return ExitUsage
		}
		if err = identityService.PasswordSet(ctx, *principalID, password, "operator:cli"); err == nil {
			result = map[string]any{"password_set": true}
		}
	case "authn login":
		password := os.Getenv(*passwordVar)
		if password == "" {
			_, _ = fmt.Fprintf(stderr, "sesame authn login: set the password in $%s\n", *passwordVar)
			return ExitUsage
		}
		result, err = login(ctx, identityService, *tenantID, *namespace, *value,
			password, os.Getenv(*totpVar), *lifetime)
	case "authn totp-enroll":
		// The secret is printed once; it is never recoverable afterwards.
		result, err = identityService.TOTPEnroll(ctx, *principalID, *issuer, "operator:cli")
	case "authn totp-activate":
		err = identityService.TOTPActivate(ctx, *principalID, *code, "operator:cli")
		result = map[string]any{"activated": err == nil}
	case "authn passkey-list":
		// Registration itself needs a browser, so the CLI offers inspection
		// and removal — the operator half of the lost-device response.
		result, err = identityService.PasskeyList(*principalID)
	case "authn passkey-remove":
		err = identityService.PasskeyRemove(ctx, *credentialID, "operator:cli")
		result = map[string]any{"removed": err == nil}
	case "session verify":
		secret := os.Getenv(*secretVar)
		if secret == "" {
			_, _ = fmt.Fprintf(stderr, "sesame session verify: set the secret in $%s\n", *secretVar)
			return ExitUsage
		}
		var verified sessiondomain.Session
		verified, err = identityService.SessionVerify(*sessionID, secret)
		verified.SecretDigest = ""
		result = verified
	case "session revoke":
		err = identityService.SessionRevoke(ctx, *sessionID, *reason, "operator:cli")
		result = map[string]any{"revoked": err == nil}
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame %s %s: %v\n", family, subcommand, err)
		return ExitFailure
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame %s %s: encode output: %v\n", family, subcommand, err)
		return ExitFailure
	}
	return ExitSuccess
}

// login runs the whole transaction so an operator has a single command that
// yields a usable session.
func login(
	ctx context.Context,
	service *identity.Service,
	tenantID, namespace, value, password, totpCode string,
	lifetime time.Duration,
) (identity.IssuedSession, error) {
	begun, err := service.AuthenticationBegin(ctx, tenantID, principaldomain.Identifier{
		Namespace: namespace,
		Value:     value,
	}, "operator:cli")
	if err != nil {
		return identity.IssuedSession{}, err
	}
	if _, err := service.AuthenticationVerifyPassword(ctx, begun.TransactionID, password, "operator:cli"); err != nil {
		return identity.IssuedSession{}, err
	}
	// A supplied code raises the session's assurance to MFA.
	if totpCode != "" {
		if _, err := service.AuthenticationVerifyTOTP(
			ctx, begun.TransactionID, totpCode, "operator:cli"); err != nil {
			return identity.IssuedSession{}, err
		}
	}
	return service.AuthenticationComplete(ctx, begun.TransactionID, lifetime, "operator:cli")
}

func writeUsage(writer io.Writer) {
	_, _ = io.WriteString(writer, `SESAME headless authentication and authorization engine

Usage:
  sesame init --deployment DIR --fylo-binary PATH [--issuer https://id.example]
  sesame doctor --deployment DIR
  sesame exec --loop [--deployment DIR | --fylo-binary PATH --fylo-root PATH]
  sesame tenant bootstrap --name NAME (--deployment DIR | --fylo-binary PATH --fylo-root PATH)
  sesame tenant get --name NAME | --tenant-id ID (with the same storage flags)
  sesame principal create --tenant-id ID --kind human|workload --identifier-namespace NS --identifier-value VALUE
  sesame principal get --principal-id ID | --tenant-id ID --identifier-namespace NS --identifier-value VALUE
  sesame principal suspend --principal-id ID
  sesame admin bootstrap --name TENANT --identifier-namespace NS --identifier-value VALUE
  sesame role create --tenant-id ID --name NAME --permissions "action=resource,..."
  sesame group create --tenant-id ID --name NAME
  sesame group member-add|member-remove --group-id ID --principal-id ID
  sesame grant create --tenant-id ID --role-id ID (--principal-id ID | --group-id ID)
  sesame grant revoke --grant-id ID
  sesame authn passkey-list --principal-id ID
  sesame authn passkey-remove --credential-id ID
  sesame authorize decide --tenant-id ID --principal-id ID --action ACTION --resource RESOURCE
  sesame client register --tenant-id ID --name NAME --type confidential|public --redirect-uris "https://app/cb,..."
  sesame client get|rotate-secret|disable --client-id ID
  sesame client consent|withdraw-consent --client-id ID --principal-id ID
  sesame token jwks (with the same storage flags)
  sesame token discovery [--authorize-endpoint PATH --token-endpoint PATH --jwks-uri PATH]
  sesame token revoke-family|family --family-id ID
  sesame version [--output text|json]
  sesame help
`)
}
