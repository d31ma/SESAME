package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/d31ma/sesame/internal/application/identity"
)

// scimFlags are every flag the provisioning family accepts.
type scimFlags struct {
	storage         *storageOptions
	tenantID        *string
	clientID        *string
	name            *string
	namespace       *string
	canManageGroups *bool
	reason          *string
}

func addSCIMFlags(flags *flag.FlagSet) *scimFlags {
	return &scimFlags{
		storage:  addStorageFlags(flags),
		tenantID: flags.String("tenant-id", "", "tenant public identifier"),
		clientID: flags.String("scim-client-id", "", "provisioning client public identifier"),
		name:     flags.String("name", "", "provisioning client display name"),
		namespace: flags.String("identifier-namespace", "",
			"identifier namespace a SCIM userName claims; defaults to email"),
		canManageGroups: flags.Bool("can-manage-groups", false,
			"allow this client to change group membership, which grants privilege"),
		reason: flags.String("reason", "", "reason recorded with a disable"),
	}
}

// scimSubcommand runs one subcommand against the service.
type scimSubcommand func(context.Context, *identity.Service, *scimFlags) (any, error)

// scimSubcommands is the subcommand table.
//
// Only the administrative operations are here. The resource operations —
// create, get, list, patch, deprovision — are deliberately absent: they are
// driven by a directory holding a bearer token over the machine protocol, and
// a CLI that could perform them would be a way to provision without the
// credential that provisioning is supposed to require.
var scimSubcommands = map[string]scimSubcommand{
	"client-register":     registerProvisioningClient,
	"client-rotate-token": rotateProvisioningToken,
	"client-disable":      disableProvisioningClient,
}

func scimSubcommandNames() []string {
	names := make([]string, 0, len(scimSubcommands))
	for name := range scimSubcommands {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// runProvisioning handles the provisioning command family.
func runProvisioning(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	subcommand, run, code := provisioningCommand(args, stderr)
	if code != ExitSuccess {
		return code
	}

	flags := flag.NewFlagSet("provisioning "+subcommand, flag.ContinueOnError)
	flags.SetOutput(stderr)
	parsed := addSCIMFlags(flags)
	if code := parseSCIMArgs(flags, parsed, subcommand, args, stderr); code != ExitSuccess {
		return code
	}

	identityService, closeStorage, err := openStorage(ctx, newLogger(stderr), *parsed.storage)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame provisioning %s: %v\n", subcommand, err)
		return ExitFailure
	}
	defer closeStorage()

	result, err := run(ctx, identityService, parsed)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame provisioning %s: %v\n", subcommand, err)
		return ExitFailure
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame provisioning %s: encode output: %v\n", subcommand, err)
		return ExitFailure
	}
	return ExitSuccess
}

func provisioningCommand(args []string, stderr io.Writer) (string, scimSubcommand, int) {
	if len(args) == 0 {
		return "", nil, provisioningUsage(stderr)
	}
	run, known := scimSubcommands[args[0]]
	if !known {
		return "", nil, provisioningUsage(stderr)
	}
	return args[0], run, ExitSuccess
}

func provisioningUsage(stderr io.Writer) int {
	_, _ = fmt.Fprintf(stderr, "usage: sesame provisioning %s [flags]\n",
		strings.Join(scimSubcommandNames(), "|"))
	return ExitUsage
}

func parseSCIMArgs(
	flags *flag.FlagSet,
	parsed *scimFlags,
	subcommand string,
	args []string,
	stderr io.Writer,
) int {
	if err := flags.Parse(args[1:]); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr,
			"sesame provisioning %s: unexpected positional arguments\n", subcommand)
		return ExitUsage
	}
	if !parsed.storage.configured() {
		_, _ = fmt.Fprintf(stderr,
			"sesame provisioning %s: --deployment or --fylo-binary/--fylo-root is required\n",
			subcommand)
		return ExitUsage
	}
	return ExitSuccess
}

func registerProvisioningClient(
	ctx context.Context,
	service *identity.Service,
	parsed *scimFlags,
) (any, error) {
	client, token, err := service.ProvisioningClientRegister(ctx, *parsed.tenantID,
		*parsed.name, *parsed.namespace, *parsed.canManageGroups, "operator:cli")
	if err != nil {
		return nil, err
	}
	// The token is printed once. It is stored as a digest, so there is
	// nothing to print later even for the operator who created it.
	return map[string]any{"client": client, "token": token}, nil
}

func rotateProvisioningToken(
	ctx context.Context,
	service *identity.Service,
	parsed *scimFlags,
) (any, error) {
	token, err := service.ProvisioningClientRotateToken(ctx, *parsed.tenantID,
		*parsed.clientID, "operator:cli")
	if err != nil {
		return nil, err
	}
	return map[string]string{"token": token}, nil
}

func disableProvisioningClient(
	ctx context.Context,
	service *identity.Service,
	parsed *scimFlags,
) (any, error) {
	err := service.ProvisioningClientDisable(ctx, *parsed.tenantID, *parsed.clientID,
		*parsed.reason, "operator:cli")
	return map[string]bool{"disabled": err == nil}, err
}
