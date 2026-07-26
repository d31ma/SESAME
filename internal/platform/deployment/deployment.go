// Package deployment defines the on-disk layout SESAME operates from: a
// validated configuration file, a private key directory, and the exclusively
// owned FYLO data root. Keys live outside FYLO documents by design.
package deployment

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/d31ma/sesame/internal/domain/token"
)

const (
	// ConfigVersion is the current deployment configuration schema.
	ConfigVersion = 1

	configFileName      = "config.json"
	keysDirName         = "keys"
	snapshotKeyFileName = "snapshot.key"
	secretsKeyFileName  = "secrets.key"
	signingKeyFileName  = "signing.key"
	fyloRootDirName     = "fylo-root"

	// SnapshotKeyBytes is the required MAC key length.
	SnapshotKeyBytes = 32
)

// Config is the persisted deployment configuration.
type Config struct {
	ConfigVersion int    `json:"config_version"`
	FYLOBinary    string `json:"fylo_binary"`
	// Issuer is the public identifier this deployment mints tokens under —
	// the host's own base URL. It is optional so a deployment that issues no
	// tokens needs no value; token issuance fails closed without it rather
	// than guessing one from a request, which is how issuer confusion starts.
	Issuer string `json:"issuer,omitempty"`
}

// Deployment is a loaded, validated deployment directory.
type Deployment struct {
	Dir         string
	Config      Config
	FYLORoot    string
	SnapshotKey []byte
	// SecretsKey seals credentials that must be read back rather than only
	// compared, such as TOTP shared secrets. It lives beside the snapshot
	// key, outside every FYLO document.
	SecretsKey []byte
	// SigningKey mints the tokens relying parties verify. Only its public
	// half is ever published, through JWKS; a stolen FYLO data root must not
	// yield the ability to sign.
	SigningKey *token.SigningKey
}

// Init creates a new deployment directory with fresh random keys. It fails
// when the directory already contains a deployment. An empty issuer is
// allowed; token issuance then fails closed until one is configured.
func Init(dir, fyloBinary, issuer string) (Deployment, error) {
	if dir == "" {
		return Deployment{}, errors.New("deployment directory is required")
	}
	if err := validateFYLOBinary(fyloBinary); err != nil {
		return Deployment{}, err
	}
	if err := ValidateIssuer(issuer); err != nil {
		return Deployment{}, err
	}
	if _, err := os.Stat(filepath.Join(dir, configFileName)); err == nil {
		return Deployment{}, fmt.Errorf("deployment already initialized in %s", dir)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Deployment{}, fmt.Errorf("create deployment directory: %w", err)
	}
	for _, sub := range []string{keysDirName, fyloRootDirName} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return Deployment{}, fmt.Errorf("create deployment directory %s: %w", sub, err)
		}
	}

	key := make([]byte, SnapshotKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return Deployment{}, fmt.Errorf("generate snapshot key: %w", err)
	}
	keyPath := filepath.Join(dir, keysDirName, snapshotKeyFileName)
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return Deployment{}, fmt.Errorf("write snapshot key: %w", err)
	}

	secretsKey := make([]byte, SnapshotKeyBytes)
	if _, err := rand.Read(secretsKey); err != nil {
		return Deployment{}, fmt.Errorf("generate secrets key: %w", err)
	}
	if err := os.WriteFile(
		filepath.Join(dir, keysDirName, secretsKeyFileName),
		[]byte(hex.EncodeToString(secretsKey)+"\n"),
		0o600,
	); err != nil {
		return Deployment{}, fmt.Errorf("write secrets key: %w", err)
	}

	signingKey, err := token.NewSigningKey()
	if err != nil {
		return Deployment{}, err
	}
	encodedSigningKey, err := token.EncodeSigningKey(signingKey)
	if err != nil {
		return Deployment{}, err
	}
	if err := os.WriteFile(
		filepath.Join(dir, keysDirName, signingKeyFileName),
		encodedSigningKey,
		0o600,
	); err != nil {
		return Deployment{}, fmt.Errorf("write signing key: %w", err)
	}

	config := Config{ConfigVersion: ConfigVersion, FYLOBinary: fyloBinary, Issuer: issuer}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return Deployment{}, fmt.Errorf("encode deployment configuration: %w", err)
	}
	configPath := filepath.Join(dir, configFileName)
	if err := os.WriteFile(configPath, append(encoded, '\n'), 0o600); err != nil {
		return Deployment{}, fmt.Errorf("write deployment configuration: %w", err)
	}

	return Load(dir)
}

// Load reads and validates an existing deployment directory, failing closed
// on schema, path, key-length, or key-permission problems.
func Load(dir string) (Deployment, error) {
	if dir == "" {
		return Deployment{}, errors.New("deployment directory is required")
	}

	if err := requireDeploymentDir(dir); err != nil {
		return Deployment{}, err
	}

	encoded, err := os.ReadFile(filepath.Join(dir, configFileName))
	if err != nil {
		return Deployment{}, fmt.Errorf("read deployment configuration: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Deployment{}, fmt.Errorf("decode deployment configuration: %w", err)
	}
	if config.ConfigVersion != ConfigVersion {
		return Deployment{}, fmt.Errorf(
			"unsupported deployment configuration version %d; this binary supports %d",
			config.ConfigVersion,
			ConfigVersion,
		)
	}
	if err := validateFYLOBinary(config.FYLOBinary); err != nil {
		return Deployment{}, err
	}
	if err := ValidateIssuer(config.Issuer); err != nil {
		return Deployment{}, err
	}

	fyloRoot := filepath.Join(dir, fyloRootDirName)
	rootInfo, err := os.Stat(fyloRoot)
	if err != nil || !rootInfo.IsDir() {
		return Deployment{}, fmt.Errorf("deployment FYLO root %s is not a directory", fyloRoot)
	}

	key, err := loadHexKey(filepath.Join(dir, keysDirName, snapshotKeyFileName))
	if err != nil {
		return Deployment{}, err
	}

	secretsKey, err := loadHexKey(filepath.Join(dir, keysDirName, secretsKeyFileName))
	if err != nil {
		return Deployment{}, err
	}

	signingKeyPath := filepath.Join(dir, keysDirName, signingKeyFileName)
	encodedSigningKey, err := readPrivateFile(signingKeyPath)
	if err != nil {
		return Deployment{}, err
	}
	signingKey, err := token.ParseSigningKey(encodedSigningKey)
	if err != nil {
		return Deployment{}, fmt.Errorf("%s: %w", signingKeyPath, err)
	}

	return Deployment{
		Dir:         dir,
		Config:      config,
		FYLORoot:    fyloRoot,
		SnapshotKey: key,
		SecretsKey:  secretsKey,
		SigningKey:  signingKey,
	}, nil
}

// requireDeploymentDir distinguishes the two ways a deployment path can be
// wrong, because the remedies are different and the raw open error tells an
// operator neither. A path that does not exist is usually a typo or an
// unmounted volume; a path that exists without a configuration has simply
// never been initialised.
func requireDeploymentDir(dir string) error {
	info, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf(
			"deployment directory %s does not exist; create it with: sesame init --deployment %s --fylo-binary /path/to/fylo",
			dir, dir)
	}
	if err != nil {
		return fmt.Errorf("deployment directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("deployment path %s is not a directory", dir)
	}
	if _, err := os.Stat(filepath.Join(dir, configFileName)); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf(
			"%s is not a SESAME deployment: no %s; initialise it with: sesame init --deployment %s --fylo-binary /path/to/fylo",
			dir, configFileName, dir)
	}
	return nil
}

func loadHexKey(path string) ([]byte, error) {
	encoded, err := readPrivateFile(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(key) != SnapshotKeyBytes {
		return nil, fmt.Errorf("key %s must be %d hex-encoded bytes", path, SnapshotKeyBytes)
	}
	return key, nil
}

// readPrivateFile reads a deployment key, refusing one any other account can
// read.
func readPrivateFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read deployment key: %w", err)
	}
	// POSIX permission bits are not meaningful on Windows; NTFS ACL checks
	// are part of the Windows support gate.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf(
			"deployment key %s is group- or world-accessible (%#o); require 0600",
			path,
			info.Mode().Perm(),
		)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read deployment key: %w", err)
	}
	return encoded, nil
}

// ValidateIssuer enforces the shape of an OIDC issuer identifier: an
// absolute https URL with no query or fragment. Relying parties compare the
// `iss` claim by exact string equality, so anything a normalizer might change
// is refused here rather than surprising a verifier later.
func ValidateIssuer(issuer string) error {
	if issuer == "" {
		return nil
	}
	parsed, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("issuer %q is not a valid URL", issuer)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		// http is refused even on loopback: an issuer identifier ends up in
		// discovery documents and signed tokens, not just a local browser
		// redirect.
		return fmt.Errorf("issuer %q must be an absolute https URL", issuer)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || strings.ContainsAny(issuer, "?#") {
		return fmt.Errorf("issuer %q must not contain a query or fragment", issuer)
	}
	if strings.HasSuffix(parsed.Path, "/") {
		return fmt.Errorf("issuer %q must not end with a slash", issuer)
	}
	return nil
}

func validateFYLOBinary(path string) error {
	if path == "" {
		return errors.New("FYLO binary path is required")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("FYLO binary path %s must be absolute", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("FYLO binary: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("FYLO binary %s is a directory", path)
	}
	return nil
}
