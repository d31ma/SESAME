// Package authenticator defines credentials and factors that prove a
// principal's identity. Verifier material is one-way: nothing in this
// package can recover a password from what it stores.
package authenticator

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	// KindPassword is the only authenticator kind in this slice.
	KindPassword = "password"

	// EventPasswordSet records a password verifier being set or replaced.
	EventPasswordSet = "authenticator.password_set"

	// MinPasswordLength follows NIST SP 800-63B: length is the primary
	// strength factor and composition rules are counterproductive.
	MinPasswordLength = 12
	// MaxPasswordLength bounds the hashing work an unauthenticated caller
	// can request.
	MaxPasswordLength = 1024

	saltBytes = 16
	keyBytes  = 32
)

// Parameters are Argon2id cost parameters. They are stored with every
// verifier so a deployment can raise them without invalidating existing
// credentials.
type Parameters struct {
	Memory      uint32 `json:"memory_kib"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
}

// CurrentParameters is the cost this binary hashes with. Raising any value
// makes existing verifiers eligible for transparent upgrade on next use.
//
// 64 MiB with one pass and four lanes is the OWASP-documented Argon2id
// configuration; the memory cost is what makes GPU attack expensive.
var CurrentParameters = Parameters{Memory: 64 * 1024, Iterations: 1, Parallelism: 4}

// AtLeast reports whether these parameters are no weaker than other in every
// dimension.
func (p Parameters) AtLeast(other Parameters) bool {
	return p.Memory >= other.Memory &&
		p.Iterations >= other.Iterations &&
		p.Parallelism >= other.Parallelism
}

func (p Parameters) validate() error {
	if p.Memory < 8*1024 {
		return errors.New("argon2id memory must be at least 8 MiB")
	}
	if p.Iterations < 1 {
		return errors.New("argon2id iterations must be at least 1")
	}
	if p.Parallelism < 1 {
		return errors.New("argon2id parallelism must be at least 1")
	}
	return nil
}

// ValidatePassword rejects passwords SESAME will not accept. It reports
// nothing about the password itself beyond why it was rejected.
func ValidatePassword(password string) error {
	if utf8.RuneCountInString(password) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if len(password) > MaxPasswordLength {
		return fmt.Errorf("password must not exceed %d bytes", MaxPasswordLength)
	}
	if !utf8.ValidString(password) {
		return errors.New("password must be valid UTF-8")
	}
	return nil
}

// NewPasswordVerifier hashes a password into an encoded Argon2id verifier
// using the current parameters and a fresh random salt.
func NewPasswordVerifier(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	return encode(CurrentParameters, salt, derive(password, salt, CurrentParameters)), nil
}

// VerifyPassword checks a password against an encoded verifier in constant
// time and reports whether the verifier should be rehashed because it was
// produced with weaker parameters than the current ones.
//
// A malformed verifier is an error, never a silent false: a deployment whose
// stored credentials cannot be parsed must fail closed rather than deny
// every login as if the passwords were wrong.
func VerifyPassword(verifier, password string) (matched bool, needsUpgrade bool, err error) {
	parameters, salt, expected, err := decode(verifier)
	if err != nil {
		return false, false, err
	}
	// The candidate is hashed even when it is obviously invalid so that
	// timing does not distinguish "too short" from "wrong".
	candidate := derive(password, salt, parameters)
	if subtle.ConstantTimeCompare(candidate, expected) != 1 {
		return false, false, nil
	}
	if err := ValidatePassword(password); err != nil {
		return false, false, nil
	}
	return true, !parameters.AtLeast(CurrentParameters), nil
}

func derive(password string, salt []byte, parameters Parameters) []byte {
	return argon2.IDKey(
		[]byte(password),
		salt,
		parameters.Iterations,
		parameters.Memory,
		parameters.Parallelism,
		keyBytes,
	)
}

// encode writes the standard PHC string so an operator can audit the cost of
// a stored verifier without SESAME running.
func encode(parameters Parameters, salt, key []byte) string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		parameters.Memory,
		parameters.Iterations,
		parameters.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

func decode(verifier string) (Parameters, []byte, []byte, error) {
	fields := strings.Split(verifier, "$")
	if len(fields) != 6 || fields[0] != "" || fields[1] != "argon2id" {
		return Parameters{}, nil, nil, errors.New("password verifier is not an argon2id PHC string")
	}
	var version int
	if _, err := fmt.Sscanf(fields[2], "v=%d", &version); err != nil {
		return Parameters{}, nil, nil, errors.New("password verifier has no argon2 version")
	}
	if version != argon2.Version {
		return Parameters{}, nil, nil, fmt.Errorf(
			"password verifier uses argon2 version %d; this binary supports %d",
			version,
			argon2.Version,
		)
	}
	var parameters Parameters
	if _, err := fmt.Sscanf(
		fields[3],
		"m=%d,t=%d,p=%d",
		&parameters.Memory,
		&parameters.Iterations,
		&parameters.Parallelism,
	); err != nil {
		return Parameters{}, nil, nil, errors.New("password verifier has malformed parameters")
	}
	if err := parameters.validate(); err != nil {
		return Parameters{}, nil, nil, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(fields[4])
	if err != nil || len(salt) < saltBytes {
		return Parameters{}, nil, nil, errors.New("password verifier has a malformed salt")
	}
	key, err := base64.RawStdEncoding.DecodeString(fields[5])
	if err != nil || len(key) != keyBytes {
		return Parameters{}, nil, nil, errors.New("password verifier has a malformed key")
	}
	return parameters, salt, key, nil
}

// PasswordSetPayload is the versioned payload of an EventPasswordSet event.
// It carries the verifier, never the password.
type PasswordSetPayload struct {
	PrincipalID string `json:"principal_id"`
	TenantID    string `json:"tenant_id"`
	Verifier    string `json:"verifier"`
}
