package adversarial_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// Federation attacks, driven through the shipped binary over the shipped
// machine protocol against a real deployment.
//
// The domain tests prove these refusals at a package boundary. These prove
// them where an attacker actually stands: on the far side of the protocol,
// against the engine an operator would deploy. A defence that existed only
// inside a package would not count.

const (
	fedIssuer   = "https://idp.adversarial.example"
	fedClientID = "sesame-at-the-idp"
	fedCallback = "https://app.example/federation/cb"
)

// hostileIDP is an OpenID Provider under an attacker's control, or a real one
// whose signing key an attacker holds. It can mint any assertion.
type hostileIDP struct {
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
}

func newHostileIDP(t *testing.T) *hostileIDP {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return &hostileIDP{rsaKey: rsaKey, ecKey: ecKey}
}

func (p *hostileIDP) discovery(t *testing.T, overrides map[string]any) string {
	t.Helper()

	document := map[string]any{
		"issuer":                                fedIssuer,
		"authorization_endpoint":                fedIssuer + "/authorize",
		"token_endpoint":                        fedIssuer + "/token",
		"jwks_uri":                              fedIssuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
	for name, value := range overrides {
		document[name] = value
	}
	return encodeJSON(t, document)
}

func (p *hostileIDP) keySet(t *testing.T) string {
	t.Helper()

	publicPoint := mustPublicPoint(t, p.ecKey)
	return encodeJSON(t, map[string]any{"keys": []map[string]string{
		{
			"kty": "RSA",
			"kid": "idp-1",
			"n":   base64.RawURLEncoding.EncodeToString(p.rsaKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.rsaKey.E)).Bytes()),
		},
		{
			"kty": "EC",
			"kid": "idp-ec",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(trimCoordinate(publicPoint[1:33])),
			"y":   base64.RawURLEncoding.EncodeToString(trimCoordinate(publicPoint[33:])),
		},
	}})
}

// mint produces an assertion. header and claim overrides let one case forge
// exactly one thing, so a refusal is attributable.
func (p *hostileIDP) mint(
	t *testing.T,
	header map[string]any,
	overrides map[string]any,
) string {
	t.Helper()

	now := time.Now()
	claims := map[string]any{
		"iss":            fedIssuer,
		"sub":            "attacker-subject",
		"aud":            fedClientID,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "victim@example.com",
		"email_verified": true,
	}
	for name, value := range overrides {
		if value == nil {
			delete(claims, name)
			continue
		}
		claims[name] = value
	}
	signing := base64.RawURLEncoding.EncodeToString([]byte(encodeJSON(t, header))) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(encodeJSON(t, claims)))
	return signing + "." + base64.RawURLEncoding.EncodeToString(p.signature(t, header, signing))
}

func (p *hostileIDP) signature(t *testing.T, header map[string]any, signing string) []byte {
	t.Helper()

	sum := sha256.Sum256([]byte(signing))
	switch header["alg"] {
	case "RS256":
		signature, err := rsa.SignPKCS1v15(rand.Reader, p.rsaKey, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatalf("sign RS256: %v", err)
		}
		return signature
	case "ES256":
		r, s, err := ecdsa.Sign(rand.Reader, p.ecKey, sum[:])
		if err != nil {
			t.Fatalf("sign ES256: %v", err)
		}
		raw := make([]byte, 64)
		r.FillBytes(raw[:32])
		s.FillBytes(raw[32:])
		return raw
	case "none":
		return nil
	default:
		// An algorithm the engine must refuse before it reaches a key, so the
		// bytes here are irrelevant.
		return []byte("forged")
	}
}

func encodeJSON(t *testing.T, value any) string {
	t.Helper()

	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

// federate registers and configures a provider on a real deployment.
func federate(t *testing.T, deploy *deployment, idp *hostileIDP) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	registered, err := deploy.client.ProviderRegister(ctx, deploy.tenantID, "Hostile IdP",
		fedIssuer, fedClientID, "idp-secret", []string{"email"},
		"sub", "email", "verified_email")
	if err != nil {
		t.Fatalf("ProviderRegister() error = %v", err)
	}
	provider, ok := registered["provider"].(map[string]any)
	if !ok {
		t.Fatalf("registration returned no provider: %#v", registered)
	}
	providerID, _ := provider["provider_id"].(string)
	if providerID == "" {
		t.Fatalf("registration returned no provider id: %#v", provider)
	}
	if _, err := deploy.client.ProviderConfigure(ctx, deploy.tenantID, providerID,
		idp.discovery(t, nil), idp.keySet(t)); err != nil {
		t.Fatalf("ProviderConfigure() error = %v", err)
	}
	return providerID
}

// startFederatedLogin opens a login and returns its id and the nonce the
// engine put in the authorization URL.
func startFederatedLogin(t *testing.T, deploy *deployment, providerID string) (string, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	started, err := deploy.client.FederatedLoginStart(ctx, deploy.tenantID, providerID, fedCallback)
	if err != nil {
		t.Fatalf("FederatedLoginStart() error = %v", err)
	}
	loginID, _ := started["login_id"].(string)
	authorizationURL, _ := started["authorization_url"].(string)
	if loginID == "" || authorizationURL == "" {
		t.Fatalf("login start returned %#v", started)
	}
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	return loginID, parsed.Query().Get("nonce")
}

// TestFederationAlgorithmConfusion is the attack family that tries to choose
// its own verification scheme.
func TestFederationAlgorithmConfusion(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	idp := newHostileIDP(t)
	providerID := federate(t, deploy, idp)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cases := map[string]map[string]any{
		// Strip the signature and declare it unnecessary.
		"alg none": {"alg": "none", "kid": "idp-1"},
		// The RSA public key as an HMAC secret. It is published, so accepting
		// this would let anyone mint assertions.
		"HS256 downgrade":   {"alg": "HS256", "kid": "idp-1"},
		"unknown algorithm": {"alg": "PS999", "kid": "idp-1"},
		// Ask the engine to read an EC key as an RSA one.
		"key type mismatch": {"alg": "RS256", "kid": "idp-ec"},
		// A key the provider does not publish.
		"unknown kid": {"alg": "RS256", "kid": "attacker-key"},
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			loginID, nonce := startFederatedLogin(t, deploy, providerID)
			_, err := deploy.client.FederatedLoginComplete(ctx, deploy.tenantID, loginID,
				idp.mint(t, header, map[string]any{"nonce": nonce}))
			refused(t, "federation "+name, err, "assertion_rejected")
		})
	}
}

// TestFederationAssertionReplay proves an assertion cannot be reused, either
// against its own spent login or against a different one.
func TestFederationAssertionReplay(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	idp := newHostileIDP(t)
	providerID := federate(t, deploy, idp)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	first, firstNonce := startFederatedLogin(t, deploy, providerID)
	assertion := idp.mint(t, map[string]any{"alg": "RS256", "kid": "idp-1"},
		map[string]any{"nonce": firstNonce})
	if _, err := deploy.client.FederatedLoginComplete(ctx, deploy.tenantID, first,
		assertion); err != nil {
		t.Fatalf("the first completion failed: %v", err)
	}

	t.Run("against its own spent login", func(t *testing.T) {
		_, err := deploy.client.FederatedLoginComplete(ctx, deploy.tenantID, first, assertion)
		refused(t, "federated assertion replay", err, "federated_login_closed")
	})

	t.Run("against a different login", func(t *testing.T) {
		second, _ := startFederatedLogin(t, deploy, providerID)
		_, err := deploy.client.FederatedLoginComplete(ctx, deploy.tenantID, second, assertion)
		refused(t, "federated assertion cross-login replay", err, "assertion_rejected")
	})
}

// TestFederationHostileDiscovery covers the documents that try to move where
// SESAME sends a credential or gets a key.
func TestFederationHostileDiscovery(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	idp := newHostileIDP(t)
	providerID := federate(t, deploy, idp)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cases := map[string]map[string]any{
		// The token endpoint receives SESAME's client secret.
		"token endpoint off origin": {"token_endpoint": "https://evil.example/token"},
		// The JWKS URI decides what key verifies an assertion.
		"jwks off origin": {"jwks_uri": "https://evil.example/jwks"},
		// The classic SSRF targets.
		"loopback jwks":       {"jwks_uri": "https://127.0.0.1/jwks"},
		"link-local token":    {"token_endpoint": "https://169.254.169.254/latest/meta-data"},
		"scheme downgrade":    {"token_endpoint": "http://idp.adversarial.example/token"},
		"issuer substitution": {"issuer": "https://evil.example"},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := deploy.client.ProviderConfigure(ctx, deploy.tenantID, providerID,
				idp.discovery(t, overrides), idp.keySet(t))
			if err == nil {
				t.Fatalf("hostile discovery (%s) SUCCEEDED; the engine accepted it", name)
			}
		})
	}
}

// TestFederationCrossTenantSubstitution proves one tenant cannot reach
// another's provider or login, and cannot learn that either exists.
func TestFederationCrossTenantSubstitution(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	idp := newHostileIDP(t)
	providerID := federate(t, deploy, idp)
	loginID, nonce := startFederatedLogin(t, deploy, providerID)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	attacker, err := deploy.client.TenantBootstrap(ctx, "attacker")
	if err != nil {
		t.Fatalf("TenantBootstrap() error = %v", err)
	}

	t.Run("provider", func(t *testing.T) {
		_, err := deploy.client.ProviderGet(ctx, attacker.Tenant.ID, providerID)
		refused(t, "cross-tenant provider read", err, "provider_not_found")
	})

	t.Run("login start", func(t *testing.T) {
		_, err := deploy.client.FederatedLoginStart(ctx, attacker.Tenant.ID, providerID, fedCallback)
		refused(t, "cross-tenant federated login start", err, "provider_not_found")
	})

	t.Run("login completion", func(t *testing.T) {
		_, err := deploy.client.FederatedLoginComplete(ctx, attacker.Tenant.ID, loginID,
			idp.mint(t, map[string]any{"alg": "RS256", "kid": "idp-1"},
				map[string]any{"nonce": nonce}))
		refused(t, "cross-tenant federated login completion", err, "federated_login_not_found")
	})

	t.Run("disable", func(t *testing.T) {
		_, err := deploy.client.ProviderDisable(ctx, attacker.Tenant.ID, providerID, "hostile")
		refused(t, "cross-tenant provider disable", err, "provider_not_found")
	})
}

// TestFederationAccountTakeover is the attack this feature most obviously
// enables if the verified-email flag is not honoured: register at the
// provider as the victim's address and claim their SESAME account.
func TestFederationAccountTakeover(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	idp := newHostileIDP(t)
	providerID := federate(t, deploy, idp)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// The deployment's principal is victim@example.com, which is exactly what
	// the hostile provider asserts.
	for name, override := range map[string]any{
		"unverified email": false,
		"absent flag":      nil,
	} {
		t.Run(name, func(t *testing.T) {
			loginID, nonce := startFederatedLogin(t, deploy, providerID)
			_, err := deploy.client.FederatedLoginComplete(ctx, deploy.tenantID, loginID,
				idp.mint(t, map[string]any{"alg": "RS256", "kid": "idp-1"}, map[string]any{
					"nonce":          nonce,
					"email_verified": override,
				}))
			refused(t, "federated account takeover via "+name, err, "subject_not_linked")
		})
	}
}

// TestFederationDisabledProviderStopsImmediately proves the operator's remedy
// for a compromised provider bites at the protocol boundary.
func TestFederationDisabledProviderStopsImmediately(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	idp := newHostileIDP(t)
	providerID := federate(t, deploy, idp)
	loginID, nonce := startFederatedLogin(t, deploy, providerID)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if _, err := deploy.client.ProviderDisable(ctx, deploy.tenantID, providerID,
		"compromised"); err != nil {
		t.Fatalf("ProviderDisable() error = %v", err)
	}
	// A login that was already in flight must not complete: the provider that
	// vouches for it is no longer trusted.
	_, err := deploy.client.FederatedLoginComplete(ctx, deploy.tenantID, loginID,
		idp.mint(t, map[string]any{"alg": "RS256", "kid": "idp-1"},
			map[string]any{"nonce": nonce}))
	refused(t, "federated login through a disabled provider", err, "provider_not_found")
}
