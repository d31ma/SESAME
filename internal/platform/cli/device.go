package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/d31ma/sesame/internal/application/identity"
)

// deviceFlags are every flag the device family accepts.
type deviceFlags struct {
	storage   *storageOptions
	tenantID  *string
	clientID  *string
	userCode  *string
	scopes    *string
	sessionID *string
}

func addDeviceFlags(flags *flag.FlagSet) *deviceFlags {
	return &deviceFlags{
		storage:  addStorageFlags(flags),
		tenantID: flags.String("tenant-id", "", "tenant public identifier"),
		clientID: flags.String("client-id", "", "OIDC client the device authenticates as"),
		userCode: flags.String("user-code", "", "the code shown on the device"),
		scopes:   flags.String("scopes", "", "comma-separated scopes the device requests"),
		sessionID: flags.String("session-id", "",
			"session approving the device; its secret is read from SESAME_SESSION_SECRET"),
	}
}

// runDevice handles the device command family.
//
// The approving session's secret is read from the environment, not a flag, for
// the same reason every other credential in this CLI is: a flag lands in shell
// history and in the process listing of anyone who can run ps.
func runDevice(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	subcommand, run, code := deviceCommand(args, stderr)
	if code != ExitSuccess {
		return code
	}

	flags := flag.NewFlagSet("device "+subcommand, flag.ContinueOnError)
	flags.SetOutput(stderr)
	parsed := addDeviceFlags(flags)
	if code := parseDeviceArgs(flags, parsed, subcommand, args, stderr); code != ExitSuccess {
		return code
	}

	identityService, closeStorage, err := openStorage(ctx, newLogger(stderr), *parsed.storage)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame device %s: %v\n", subcommand, err)
		return ExitFailure
	}
	defer closeStorage()

	result, err := run(ctx, identityService, parsed)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame device %s: %v\n", subcommand, err)
		return ExitFailure
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame device %s: encode output: %v\n", subcommand, err)
		return ExitFailure
	}
	return ExitSuccess
}

func parseDeviceArgs(
	flags *flag.FlagSet,
	parsed *deviceFlags,
	subcommand string,
	args []string,
	stderr io.Writer,
) int {
	if err := flags.Parse(args[1:]); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "sesame device %s: unexpected positional arguments\n", subcommand)
		return ExitUsage
	}
	if !parsed.storage.configured() {
		_, _ = fmt.Fprintf(stderr,
			"sesame device %s: --deployment or --fylo-binary/--fylo-root is required\n", subcommand)
		return ExitUsage
	}
	return ExitSuccess
}

// deviceSubcommand runs one subcommand against the service.
type deviceSubcommand func(context.Context, *identity.Service, *deviceFlags) (any, error)

var deviceSubcommands = map[string]deviceSubcommand{
	"authorize": func(ctx context.Context, service *identity.Service, parsed *deviceFlags) (any, error) {
		return service.DeviceAuthorizationStart(ctx, *parsed.clientID,
			splitList(*parsed.scopes), "operator:cli")
	},
	"lookup": func(_ context.Context, service *identity.Service, parsed *deviceFlags) (any, error) {
		return service.DeviceAuthorizationLookup(*parsed.tenantID, *parsed.userCode)
	},
	"approve": func(ctx context.Context, service *identity.Service, parsed *deviceFlags) (any, error) {
		return service.DeviceAuthorizationApprove(ctx, *parsed.tenantID, *parsed.userCode,
			*parsed.sessionID, os.Getenv("SESAME_SESSION_SECRET"), "operator:cli")
	},
	"deny": func(ctx context.Context, service *identity.Service, parsed *deviceFlags) (any, error) {
		err := service.DeviceAuthorizationDeny(ctx, *parsed.tenantID, *parsed.userCode, "operator:cli")
		return map[string]bool{"denied": err == nil}, err
	},
}

func deviceSubcommandNames() []string {
	names := make([]string, 0, len(deviceSubcommands))
	for name := range deviceSubcommands {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func deviceCommand(args []string, stderr io.Writer) (string, deviceSubcommand, int) {
	if len(args) == 0 {
		_, _ = fmt.Fprintf(stderr, "usage: sesame device %s [flags]\n",
			strings.Join(deviceSubcommandNames(), "|"))
		return "", nil, ExitUsage
	}
	run, known := deviceSubcommands[args[0]]
	if !known {
		_, _ = fmt.Fprintf(stderr, "usage: sesame device %s [flags]\n",
			strings.Join(deviceSubcommandNames(), "|"))
		return "", nil, ExitUsage
	}
	return args[0], run, ExitSuccess
}
