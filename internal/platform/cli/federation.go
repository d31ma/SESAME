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

// federationFlags are every flag the federation family accepts. Gathering
// them in one struct keeps runFederation a short sequence of steps rather
// than a wall of declarations.
type federationFlags struct {
	storage      *storageOptions
	tenantID     *string
	providerID   *string
	loginID      *string
	name         *string
	issuer       *string
	clientID     *string
	scopes       *string
	subjectClaim *string
	emailClaim   *string
	linking      *string
	discovery    *string
	keySet       *string
	redirectURI  *string
	state        *string
	code         *string
	idToken      *string
	reason       *string
}

func addFederationFlags(flags *flag.FlagSet) *federationFlags {
	return &federationFlags{
		storage:    addStorageFlags(flags),
		tenantID:   flags.String("tenant-id", "", "tenant public identifier"),
		providerID: flags.String("provider-id", "", "identity provider public identifier"),
		loginID:    flags.String("login-id", "", "federated login public identifier"),
		name:       flags.String("name", "", "provider display name"),
		issuer:     flags.String("issuer", "", "the provider's exact issuer, https and no trailing slash"),
		clientID:   flags.String("client-id", "", "what the provider knows SESAME as"),
		scopes:     flags.String("scopes", "", "comma-separated scopes; openid is always included"),
		subjectClaim: flags.String("subject-claim", "sub",
			"claim carrying the provider's stable user identifier"),
		emailClaim: flags.String("email-claim", "",
			"claim carrying an email address, required by verified_email linking"),
		linking: flags.String("linking", "strict",
			"strict requires an existing link; verified_email matches or provisions"),
		discovery: flags.String("discovery", "",
			"path to the fetched discovery document"),
		keySet:      flags.String("key-set", "", "path to the fetched JWKS document"),
		redirectURI: flags.String("redirect-uri", "", "where the provider returns the browser"),
		state:       flags.String("state", "", "the state returned on the callback"),
		code:        flags.String("code", "", "the authorization code returned on the callback"),
		idToken:     flags.String("id-token", "", "the ID token from the provider's token response"),
		reason:      flags.String("reason", "", "reason recorded with a disable"),
	}
}

// runFederation handles the federation command family.
//
// The provider's client secret is read from SESAME_PROVIDER_CLIENT_SECRET
// rather than a flag, for the same reason every other credential in this CLI
// is: a flag lands in shell history and in the process listing of anyone who
// can run ps.
func runFederation(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	subcommand, run, code := federationCommand(args, stderr)
	if code != ExitSuccess {
		return code
	}

	flags := flag.NewFlagSet("federation "+subcommand, flag.ContinueOnError)
	flags.SetOutput(stderr)
	parsed := addFederationFlags(flags)
	if code := parseFederationArgs(flags, parsed, subcommand, args, stderr); code != ExitSuccess {
		return code
	}

	identityService, closeStorage, err := openStorage(ctx, newLogger(stderr), *parsed.storage)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame federation %s: %v\n", subcommand, err)
		return ExitFailure
	}
	defer closeStorage()

	result, err := run(ctx, identityService, parsed)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame federation %s: %v\n", subcommand, err)
		return ExitFailure
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame federation %s: encode output: %v\n", subcommand, err)
		return ExitFailure
	}
	return ExitSuccess
}

// parseFederationArgs validates the command line before any storage is opened.
func parseFederationArgs(
	flags *flag.FlagSet,
	parsed *federationFlags,
	subcommand string,
	args []string,
	stderr io.Writer,
) int {
	if err := flags.Parse(args[1:]); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "sesame federation %s: unexpected positional arguments\n",
			subcommand)
		return ExitUsage
	}
	if !parsed.storage.configured() {
		_, _ = fmt.Fprintf(stderr,
			"sesame federation %s: --deployment or --fylo-binary/--fylo-root is required\n",
			subcommand)
		return ExitUsage
	}
	return ExitSuccess
}

// federationSubcommand runs one subcommand against the service.
type federationSubcommand func(context.Context, *identity.Service, *federationFlags) (any, error)

// federationSubcommands is the subcommand table. A switch would put every
// subcommand's existence into one function's complexity; a map makes each one
// data.
var federationSubcommands = map[string]federationSubcommand{
	"provider-register":  registerProvider,
	"provider-configure": configureProvider,
	"provider-disable":   disableProvider,
	"provider-get": func(_ context.Context, service *identity.Service, parsed *federationFlags) (any, error) {
		return service.ProviderGet(*parsed.tenantID, *parsed.providerID)
	},
	"login-start": func(ctx context.Context, service *identity.Service, parsed *federationFlags) (any, error) {
		return service.LoginStart(ctx, *parsed.tenantID, *parsed.providerID,
			*parsed.redirectURI, "operator:cli")
	},
	"login-exchange": func(ctx context.Context, service *identity.Service, parsed *federationFlags) (any, error) {
		return service.LoginExchange(ctx, *parsed.tenantID, *parsed.loginID,
			*parsed.state, *parsed.code)
	},
	"login-complete": func(ctx context.Context, service *identity.Service, parsed *federationFlags) (any, error) {
		return service.LoginComplete(ctx, *parsed.tenantID, *parsed.loginID,
			*parsed.idToken, "operator:cli")
	},
}

func federationSubcommandNames() []string {
	names := make([]string, 0, len(federationSubcommands))
	for name := range federationSubcommands {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func disableProvider(
	ctx context.Context,
	service *identity.Service,
	parsed *federationFlags,
) (any, error) {
	err := service.ProviderDisable(ctx, *parsed.tenantID, *parsed.providerID,
		*parsed.reason, "operator:cli")
	return map[string]bool{"disabled": err == nil}, err
}

func registerProvider(
	ctx context.Context,
	service *identity.Service,
	parsed *federationFlags,
) (any, error) {
	provider, instruction, err := service.ProviderRegister(ctx,
		*parsed.tenantID, *parsed.name, *parsed.issuer, *parsed.clientID,
		os.Getenv("SESAME_PROVIDER_CLIENT_SECRET"), splitList(*parsed.scopes),
		*parsed.subjectClaim, *parsed.emailClaim, *parsed.linking, "operator:cli")
	if err != nil {
		return nil, err
	}
	// The instruction travels with the provider: registration is not usable
	// until an operator fetches what it names and runs provider-configure.
	return map[string]any{"provider": provider, "fetch": instruction}, nil
}

func configureProvider(
	ctx context.Context,
	service *identity.Service,
	parsed *federationFlags,
) (any, error) {
	discovery, err := os.ReadFile(*parsed.discovery)
	if err != nil {
		return nil, fmt.Errorf("read the discovery document: %w", err)
	}
	keySet, err := os.ReadFile(*parsed.keySet)
	if err != nil {
		return nil, fmt.Errorf("read the key set: %w", err)
	}
	return service.ProviderConfigure(ctx, *parsed.tenantID, *parsed.providerID,
		discovery, keySet, "operator:cli")
}

// federationCommand resolves the subcommand, or prints usage.
func federationCommand(args []string, stderr io.Writer) (string, federationSubcommand, int) {
	if len(args) == 0 {
		_, _ = fmt.Fprintf(stderr, "usage: sesame federation %s [flags]\n",
			strings.Join(federationSubcommandNames(), "|"))
		return "", nil, ExitUsage
	}
	run, known := federationSubcommands[args[0]]
	if !known {
		_, _ = fmt.Fprintf(stderr, "usage: sesame federation %s [flags]\n",
			strings.Join(federationSubcommandNames(), "|"))
		return "", nil, ExitUsage
	}
	return args[0], run, ExitSuccess
}
