package machine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

const (
	dpopIssuer   = "https://id.example"
	dpopTokenURL = dpopIssuer + "/oauth/token"
	dpopAPIURL   = dpopIssuer + "/api/invoices"
)

// machineDPoPKey mints proofs over the wire the way a client would.
type machineDPoPKey struct {
	private     *ecdsa.PrivateKey
	publicPoint []byte
}

func newMachineDPoPKey(t *testing.T) *machineDPoPKey {
	t.Helper()

	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate DPoP key: %v", err)
	}
	return &machineDPoPKey{private: private, publicPoint: mustPublicPoint(t, private)}
}

func mustPublicPoint(t testing.TB, private *ecdsa.PrivateKey) []byte {
	t.Helper()

	point, err := private.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}
	return point
}

func (m *machineDPoPKey) proof(t *testing.T, id, method, uri, accessToken string) string {
	t.Helper()

	body := map[string]any{
		"jti": id, "htm": method, "htu": uri, "iat": time.Now().Unix(),
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		body["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	encode := func(value any) string {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(encoded)
	}
	input := encode(map[string]any{
		"typ": "dpop+jwt", "alg": "ES256",
		"jwk": map[string]any{
			"kty": "EC", "crv": "P-256",
			"x": base64.RawURLEncoding.EncodeToString(
				m.publicPoint[1:33]),
			"y": base64.RawURLEncoding.EncodeToString(
				m.publicPoint[33:]),
		},
	}) + "." + encode(body)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, m.private, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// TestDPoPEdgeBindsAndVerifiesOverTheWire walks the whole scheme through the
// protocol: a proof at the token endpoint binds the token, and a second proof
// at a resource proves the same key still holds it.
func TestDPoPEdgeBindsAndVerifiesOverTheWire(t *testing.T) {
	t.Parallel()

	processor, clientID, clientSecret, sessionID, sessionSecret := pushedEdge(t)
	key := newMachineDPoPKey(t)

	started := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"d1","operation":"oidc.authorize",`+
			`"parameters":{"client_id":"`+clientID+
			`","redirect_uri":"`+pushedRedirectURI+
			`","response_type":"code","scopes":["profile"],`+
			`"code_challenge":"`+pushedChallenge()+`","code_challenge_method":"S256"}}`)
	if !started[0].OK {
		t.Fatalf("authorize failed: %+v", started[0].Error)
	}
	var interaction struct {
		InteractionID string `json:"interaction_id"`
		Secret        string `json:"interaction_secret"`
	}
	decodeResult(t, started[0].Result, &interaction)

	completed := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"d2","operation":"oidc.interaction_complete",`+
			`"parameters":{"interaction_id":"`+interaction.InteractionID+
			`","interaction_secret":`+jsonString(t, interaction.Secret)+
			`,"session_id":"`+sessionID+
			`","session_secret":`+jsonString(t, sessionSecret)+`}}`)
	if !completed[0].OK {
		t.Fatalf("interaction_complete failed: %+v", completed[0].Error)
	}
	var authorization struct {
		Code string `json:"code"`
	}
	decodeResult(t, completed[0].Result, &authorization)

	tokens := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"d3","operation":"oidc.token",`+
			`"parameters":{"grant_type":"authorization_code","code":`+
			jsonString(t, authorization.Code)+
			`,"redirect_uri":"`+pushedRedirectURI+
			`","client_id":"`+clientID+
			`","client_secret":`+jsonString(t, clientSecret)+
			`,"code_verifier":`+jsonString(t, pushedVerifier)+
			`,"dpop_proof":`+jsonString(t, key.proof(t, "token-1", "POST", dpopTokenURL, ""))+
			`,"http_method":"POST","http_uri":`+jsonString(t, dpopTokenURL)+`}}`)
	if !tokens[0].OK {
		t.Fatalf("a DPoP token exchange failed: %+v", tokens[0].Error)
	}
	var issued struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	decodeResult(t, tokens[0].Result, &issued)
	// The type is part of the contract: a client that sends a DPoP token as
	// `Bearer` should be corrected by the response it got, not by a support
	// ticket.
	if issued.TokenType != "DPoP" {
		t.Fatalf("token_type = %q, want DPoP", issued.TokenType)
	}

	verified := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"d4","operation":"oidc.dpop_verify",`+
			`"parameters":{"access_token":`+jsonString(t, issued.AccessToken)+
			`,"dpop_proof":`+jsonString(t,
			key.proof(t, "api-1", "GET", dpopAPIURL, issued.AccessToken))+
			`,"http_method":"GET","http_uri":`+jsonString(t, dpopAPIURL)+`}}`)
	if !verified[0].OK {
		t.Fatalf("dpop_verify failed: %+v", verified[0].Error)
	}
	var verification struct {
		Active     bool   `json:"active"`
		Thumbprint string `json:"dpop_thumbprint"`
	}
	decodeResult(t, verified[0].Result, &verification)
	if !verification.Active || verification.Thumbprint == "" {
		t.Fatalf("verification = %#v", verification)
	}
}

// TestDPoPEdgeCodesAreStable. A host maps these onto the single
// `invalid_token` RFC 9449 allows at the HTTP boundary; renaming one here
// breaks that mapping and every log built on it.
func TestDPoPEdgeCodesAreStable(t *testing.T) {
	t.Parallel()

	processor, _, _, _, _ := pushedEdge(t)
	key := newMachineDPoPKey(t)

	verify := func(t *testing.T, id, proof, method, uri string) Response {
		t.Helper()
		return runRequests(t, processor,
			`{"protocol_version":"1","request_id":"`+id+`","operation":"oidc.dpop_verify",`+
				`"parameters":{"access_token":"some.access.token","dpop_proof":`+
				jsonString(t, proof)+`,"http_method":`+jsonString(t, method)+
				`,"http_uri":`+jsonString(t, uri)+`}}`)[0]
	}

	for name, testCase := range map[string]struct {
		id, proof, method, uri, want string
	}{
		"a malformed proof": {"e1", "not-a-jws", "GET", dpopAPIURL, ErrorDPoPProofInvalid},
		"a proof for another method": {
			"e2", key.proof(t, "p1", "POST", dpopAPIURL, "some.access.token"),
			"GET", dpopAPIURL, ErrorDPoPProofNotBound,
		},
		"a proof with no ath": {
			"e3", key.proof(t, "p2", "GET", dpopAPIURL, ""),
			"GET", dpopAPIURL, ErrorDPoPProofNotBound,
		},
		"a proof for another issuer": {
			"e4", key.proof(t, "p3", "GET", "https://evil.example/api", "some.access.token"),
			"GET", "https://evil.example/api", ErrorDPoPForeignOrigin,
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := verify(t, testCase.id, testCase.proof, testCase.method, testCase.uri)
			if response.OK {
				t.Fatalf("%s was accepted", name)
			}
			if response.Error.Code != testCase.want {
				t.Fatalf("%s: error code = %q, want %q", name, response.Error.Code, testCase.want)
			}
		})
	}

	t.Run("a replayed proof", func(t *testing.T) {
		proof := key.proof(t, "replay-1", "GET", dpopAPIURL, "some.access.token")
		if first := verify(t, "r1", proof, "GET", dpopAPIURL); !first.OK {
			t.Fatalf("the first use failed: %+v", first.Error)
		}
		second := verify(t, "r2", proof, "GET", dpopAPIURL)
		if second.OK {
			t.Fatal("a replayed proof was accepted")
		}
		if second.Error.Code != ErrorDPoPProofReplayed {
			t.Fatalf("error code = %q, want %q", second.Error.Code, ErrorDPoPProofReplayed)
		}
	})
}

// TestDPoPEdgeRefusesWithoutStorage. Fail closed.
func TestDPoPEdgeRefusesWithoutStorage(t *testing.T) {
	t.Parallel()

	processor := New(nil, nil)
	responses := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"s1","operation":"oidc.dpop_verify",`+
			`"parameters":{"access_token":"a","dpop_proof":"b","http_method":"GET",`+
			`"http_uri":"https://id.example/api"}}`)
	if responses[0].OK {
		t.Fatal("dpop_verify succeeded without storage")
	}
	if responses[0].Error.Code != ErrorStorageNotConfigured {
		t.Fatalf("error code = %q, want %q", responses[0].Error.Code, ErrorStorageNotConfigured)
	}
}
