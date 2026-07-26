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
	samldomain "github.com/d31ma/sesame/internal/domain/saml"
)

// samlFlags are every flag the saml family accepts.
type samlFlags struct {
	storage      *storageOptions
	tenantID     *string
	providerID   *string
	loginID      *string
	name         *string
	entityID     *string
	ssoURL       *string
	certificates *string
	namespace    *string
	linking      *string
	consumerURL  *string
	assertion    *string
	reason       *string
}

func addSAMLFlags(flags *flag.FlagSet) *samlFlags {
	return &samlFlags{
		storage:    addStorageFlags(flags),
		tenantID:   flags.String("tenant-id", "", "tenant public identifier"),
		providerID: flags.String("provider-id", "", "SAML provider public identifier"),
		loginID:    flags.String("login-id", "", "SAML login public identifier"),
		name:       flags.String("name", "", "provider display name"),
		entityID: flags.String("entity-id", "",
			"the provider's exact entity ID, compared byte-for-byte against an assertion's Issuer"),
		ssoURL: flags.String("sso-url", "", "the provider's https single sign-on endpoint"),
		certificates: flags.String("certificate", "",
			"comma-separated paths to the provider's signing certificates; several is normal during a rotation"),
		namespace: flags.String("identifier-namespace", "email",
			"SESAME namespace a NameID claims; SAML does not require a NameID to be an email"),
		linking: flags.String("linking", "strict",
			"strict requires an existing link; verified_email matches or provisions"),
		consumerURL: flags.String("consumer-url", "",
			"where the host receives the assertion; checked against the assertion's Recipient"),
		assertion: flags.String("assertion", "",
			"path to the base64 SAMLResponse the host received"),
		reason: flags.String("reason", "", "reason recorded with a disable"),
	}
}

// runSAML handles the saml command family.
func runSAML(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	subcommand, run, code := samlCommand(args, stderr)
	if code != ExitSuccess {
		return code
	}

	flags := flag.NewFlagSet("saml "+subcommand, flag.ContinueOnError)
	flags.SetOutput(stderr)
	parsed := addSAMLFlags(flags)
	if code := parseSAMLArgs(flags, parsed, subcommand, args, stderr); code != ExitSuccess {
		return code
	}

	identityService, closeStorage, err := openStorage(ctx, newLogger(stderr), *parsed.storage)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame saml %s: %v\n", subcommand, err)
		return ExitFailure
	}
	defer closeStorage()

	result, err := run(ctx, identityService, parsed)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame saml %s: %v\n", subcommand, err)
		return ExitFailure
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		_, _ = fmt.Fprintf(stderr, "sesame saml %s: encode output: %v\n", subcommand, err)
		return ExitFailure
	}
	return ExitSuccess
}

func parseSAMLArgs(
	flags *flag.FlagSet,
	parsed *samlFlags,
	subcommand string,
	args []string,
	stderr io.Writer,
) int {
	if err := flags.Parse(args[1:]); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "sesame saml %s: unexpected positional arguments\n", subcommand)
		return ExitUsage
	}
	if !parsed.storage.configured() {
		_, _ = fmt.Fprintf(stderr,
			"sesame saml %s: --deployment or --fylo-binary/--fylo-root is required\n", subcommand)
		return ExitUsage
	}
	return ExitSuccess
}

// samlSubcommand runs one subcommand against the service.
type samlSubcommand func(context.Context, *identity.Service, *samlFlags) (any, error)

var samlSubcommands = map[string]samlSubcommand{
	"provider-register": registerSAMLProvider,
	"provider-disable":  disableSAMLProvider,
	"provider-get": func(_ context.Context, service *identity.Service, parsed *samlFlags) (any, error) {
		return service.SAMLProviderGet(*parsed.tenantID, *parsed.providerID)
	},
	"login-start": func(ctx context.Context, service *identity.Service, parsed *samlFlags) (any, error) {
		return service.SAMLLoginStart(ctx, *parsed.tenantID, *parsed.providerID,
			*parsed.consumerURL, "operator:cli")
	},
	"login-complete": completeSAMLLogin,
}

func samlSubcommandNames() []string {
	names := make([]string, 0, len(samlSubcommands))
	for name := range samlSubcommands {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func registerSAMLProvider(
	ctx context.Context,
	service *identity.Service,
	parsed *samlFlags,
) (any, error) {
	certificates, err := readCertificateFiles(splitList(*parsed.certificates))
	if err != nil {
		return nil, err
	}
	return service.SAMLProviderRegister(ctx, *parsed.tenantID, *parsed.name,
		*parsed.entityID, *parsed.ssoURL, certificates, *parsed.namespace,
		*parsed.linking, "operator:cli")
}

// readCertificateFiles reads each certificate from a file rather than a flag.
// A certificate is public, but PEM on a command line is unreadable and easy to
// mangle; a path is neither.
func readCertificateFiles(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("--certificate is required")
	}
	certificates := make([]string, 0, len(paths))
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read the signing certificate: %w", err)
		}
		certificates = append(certificates, string(content))
	}
	return certificates, nil
}

func disableSAMLProvider(
	ctx context.Context,
	service *identity.Service,
	parsed *samlFlags,
) (any, error) {
	err := service.SAMLProviderDisable(ctx, *parsed.tenantID, *parsed.providerID,
		*parsed.reason, "operator:cli")
	return map[string]bool{"disabled": err == nil}, err
}

func completeSAMLLogin(
	ctx context.Context,
	service *identity.Service,
	parsed *samlFlags,
) (any, error) {
	encoded, err := os.ReadFile(*parsed.assertion)
	if err != nil {
		return nil, fmt.Errorf("read the SAML response: %w", err)
	}
	document, err := samldomain.DecodeResponse(string(encoded))
	if err != nil {
		return nil, err
	}
	return service.SAMLLoginComplete(ctx, *parsed.tenantID, *parsed.loginID,
		document, "operator:cli")
}

func samlCommand(args []string, stderr io.Writer) (string, samlSubcommand, int) {
	if len(args) == 0 {
		_, _ = fmt.Fprintf(stderr, "usage: sesame saml %s [flags]\n",
			strings.Join(samlSubcommandNames(), "|"))
		return "", nil, ExitUsage
	}
	run, known := samlSubcommands[args[0]]
	if !known {
		_, _ = fmt.Fprintf(stderr, "usage: sesame saml %s [flags]\n",
			strings.Join(samlSubcommandNames(), "|"))
		return "", nil, ExitUsage
	}
	return args[0], run, ExitSuccess
}
