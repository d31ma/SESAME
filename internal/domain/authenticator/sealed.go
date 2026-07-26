package authenticator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Some credentials cannot be hashed. A password is only ever compared, so a
// one-way verifier is enough; a TOTP shared secret must be read back to
// compute the expected code. Those are sealed with AES-256-GCM under a key
// held in the deployment key directory, outside every FYLO document.
//
// This is SESAME's own envelope rather than FYLO's field encryption: FYLO's
// key is process-global and its decryption does not engage on read-only
// replay (FYLO issue #84), so a sealed secret would come back as ciphertext
// on restart. Owning the envelope also keeps the key scoped to SESAME.

const (
	// SealedSecretKeyBytes is the required AES-256 key length.
	SealedSecretKeyBytes = 32

	sealedPrefix = "sealed.v1."
)

// ErrNoSealingKey reports an operation that needs the deployment's secret
// key when none is configured. Enrolling a recoverable credential without a
// key would mean storing it in the clear, so it fails closed instead.
var ErrNoSealingKey = errors.New("no secret sealing key is configured; run sesame init to create a deployment")

// Seal encrypts a recoverable secret for storage. The result is a versioned,
// self-describing string safe to place in a security event.
func Seal(key []byte, plaintext string) (string, error) {
	stream, err := sealingStream(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, stream.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate sealing nonce: %w", err)
	}
	// The prefix is authenticated so a value cannot be moved between
	// envelope versions without detection.
	sealed := stream.Seal(nil, nonce, []byte(plaintext), []byte(sealedPrefix))
	return sealedPrefix +
		base64.RawURLEncoding.EncodeToString(nonce) + "." +
		base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Open decrypts a sealed secret. A wrong key, a truncated value, or any
// tampering fails rather than returning a plausible-looking secret.
func Open(key []byte, sealed string) (string, error) {
	stream, err := sealingStream(key)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(sealed, sealedPrefix) {
		return "", errors.New("value is not a sealed secret")
	}
	fields := strings.Split(strings.TrimPrefix(sealed, sealedPrefix), ".")
	if len(fields) != 2 {
		return "", errors.New("sealed secret is malformed")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(fields[0])
	if err != nil || len(nonce) != stream.NonceSize() {
		return "", errors.New("sealed secret has a malformed nonce")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(fields[1])
	if err != nil {
		return "", errors.New("sealed secret has malformed ciphertext")
	}
	plaintext, err := stream.Open(nil, nonce, ciphertext, []byte(sealedPrefix))
	if err != nil {
		return "", errors.New("sealed secret failed authentication")
	}
	return string(plaintext), nil
}

func sealingStream(key []byte) (cipher.AEAD, error) {
	if len(key) == 0 {
		return nil, ErrNoSealingKey
	}
	if len(key) != SealedSecretKeyBytes {
		return nil, fmt.Errorf("sealing key must be %d bytes", SealedSecretKeyBytes)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("prepare sealing cipher: %w", err)
	}
	stream, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("prepare sealing mode: %w", err)
	}
	return stream, nil
}
