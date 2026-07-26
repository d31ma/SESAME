package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	tokendomain "github.com/d31ma/sesame/internal/domain/token"
)

// DPoP binding, application side.
//
// The domain decides whether a proof is well formed, signed, and bound to the
// method, URI, and token it claims. What is left here is everything that needs
// state: refusing a proof whose identifier has already been spent, recording
// that it has, and carrying the resulting thumbprint through issuance,
// rotation, and verification so a token stays tied to the key it was issued
// to.

// Stable DPoP errors at the application boundary.
var (
	// ErrDPoPProofReplayed reports a proof identifier presented twice. It is
	// distinct from a malformed proof because it is the one failure that means
	// something is wrong rather than something is broken.
	ErrDPoPProofReplayed = errors.New("DPoP proof has already been used")
	// ErrDPoPProofForeignOrigin reports a proof for a URI outside this
	// deployment's issuer origin.
	ErrDPoPProofForeignOrigin = errors.New("DPoP proof names a URI outside this issuer")
	// ErrDPoPRequired reports a token bound to a key presented without a
	// proof. Fail closed: a bound token used as a bearer token is exactly the
	// theft the binding exists to catch.
	ErrDPoPRequired = errors.New("this token is key-bound and requires a DPoP proof")
)

// dpopProofRecord is one spent proof identifier, held only until its window
// closes.
type dpopProofRecord struct {
	ID         string `json:"dpop_proof_id"`
	Thumbprint string `json:"dpop_thumbprint"`
	TenantID   string `json:"tenant_id"`
	ExpiresAt  string `json:"expires_at"`
}

// DPoPProofState is one spent proof identifier in a snapshot.
type DPoPProofState struct {
	Proof dpopProofRecord `json:"proof"`
}

// DPoPVerification is what a resource server learns about a presented token.
type DPoPVerification struct {
	Active      bool     `json:"active"`
	TenantID    string   `json:"tenant_id,omitempty"`
	PrincipalID string   `json:"principal_id,omitempty"`
	ClientID    string   `json:"client_id,omitempty"`
	SessionID   string   `json:"session_id,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	// Thumbprint is the key the token is bound to, echoed so a caller can log
	// which key was proved rather than only that one was.
	Thumbprint string `json:"dpop_thumbprint,omitempty"`
	ExpiresAt  int64  `json:"expires_at,omitempty"`
}

// DPoPVerify checks a key-bound access token against a fresh proof.
//
// This is the resource-server half of DPoP, and without it the binding decides
// nothing: an authorization server that stamps `cnf.jkt` into a token and has
// no way to check it later has moved the problem rather than solved it. A host
// protecting a resource passes the token, the proof, and the method and URI it
// actually served, and gets back either an active grant or a refusal.
//
// The order matters. The proof is validated and its identifier spent before
// the token's own state is consulted, so a replayed proof is refused as a
// replay whatever the token turns out to be — and a caller cannot use the
// verification surface to probe which tokens exist by watching for a different
// failure.
func (s *Service) DPoPVerify(
	ctx context.Context,
	accessToken, proof, method, uri, actor string,
) (DPoPVerification, error) {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return DPoPVerification{}, err
	}
	if s.signingKey == nil {
		return DPoPVerification{}, tokendomain.ErrNoSigningKey
	}
	if s.issuer == "" {
		return DPoPVerification{}, ErrNoIssuer
	}
	if accessToken == "" {
		return DPoPVerification{}, fmt.Errorf("%w: no access token was presented",
			oidcdomain.ErrDPoPProofNotBound)
	}

	parsed, err := oidcdomain.ParseDPoPProof(proof)
	if err != nil {
		return DPoPVerification{}, err
	}
	// The token is passed to the binding check, so `ath` is required here. A
	// proof without one would be valid at every endpoint at once.
	if err := parsed.BindProofToRequest(method, uri, accessToken, s.now()); err != nil {
		return DPoPVerification{}, err
	}
	if !oidcdomain.SameOrigin(uri, s.issuer) {
		return DPoPVerification{}, ErrDPoPProofForeignOrigin
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	claims, body, err := s.signingKey.Verify(accessToken, s.issuer, "", s.now())
	tenantID := ""
	if err == nil {
		tenantID, _ = body["tenant_id"].(string)
	}
	// Spend the proof whatever the token turns out to be. A proof rejected
	// without being spent could be retried against a different token until one
	// stuck, which is the offline search the replay store exists to prevent.
	if spendErr := s.spendDPoPProofLocked(ctx, parsed, tenantID, actor); spendErr != nil {
		return DPoPVerification{}, spendErr
	}
	if err != nil {
		return DPoPVerification{Active: false}, nil
	}

	bound, _ := confirmationThumbprint(body)
	if bound == "" {
		// A token with no binding is a bearer token. Reporting it active here
		// would let a caller present any bearer token with any proof and be
		// told the pair verified.
		return DPoPVerification{Active: false}, nil
	}
	if bound != parsed.Thumbprint {
		return DPoPVerification{}, oidcdomain.ErrDPoPKeyMismatch
	}

	// The grant behind the token has to still be alive. A revoked session or a
	// suspended principal must stop a bound token exactly as it stops a bearer
	// one; key binding is orthogonal to revocation, not a substitute for it.
	sessionID, _ := body["sid"].(string)
	if !s.grantStandsLocked(sessionID, claims.Subject) {
		return DPoPVerification{Active: false}, nil
	}

	scope, _ := body["scope"].(string)
	return DPoPVerification{
		Active:      true,
		TenantID:    tenantID,
		PrincipalID: claims.Subject,
		ClientID:    claims.Audience,
		SessionID:   sessionID,
		Scopes:      splitScopes(scope),
		Thumbprint:  bound,
		ExpiresAt:   claims.ExpiresAt,
	}, nil
}

// tokenRequestThumbprint validates the proof accompanying a token request and
// returns the key it proves possession of.
//
// An empty proof yields an empty thumbprint and no error: DPoP is optional per
// request, and a client that does not use it gets the bearer token it asked
// for. What is *not* optional is consistency — a refresh token issued to a key
// is refused without a matching proof, which is checked by the caller that
// knows what the stored grant was bound to.
func (s *Service) tokenRequestThumbprint(
	ctx context.Context,
	request TokenRequest,
	tenantID, actor string,
) (string, error) {
	if request.DPoPProof == "" {
		return "", nil
	}
	parsed, err := oidcdomain.ParseDPoPProof(request.DPoPProof)
	if err != nil {
		return "", err
	}
	// No access token exists yet at the token endpoint, so no `ath` is
	// expected or accepted as meaningful here.
	if err := parsed.BindProofToRequest(request.DPoPMethod, request.DPoPURI, "", s.now()); err != nil {
		return "", err
	}
	if !oidcdomain.SameOrigin(request.DPoPURI, s.issuer) {
		return "", ErrDPoPProofForeignOrigin
	}
	if err := s.spendDPoPProofLocked(ctx, parsed, tenantID, actor); err != nil {
		return "", err
	}
	return parsed.Thumbprint, nil
}

// spendDPoPProofLocked records a proof identifier, refusing a second use.
//
// Identifiers are scoped by key: `jti` is required to be unique per client, not
// globally, so treating one client's identifier as a replay of another's would
// refuse a legitimate request for no gain.
func (s *Service) spendDPoPProofLocked(
	ctx context.Context,
	proof oidcdomain.DPoPProof,
	tenantID, actor string,
) error {
	now := s.now()
	// This is the only moment the map grows, so it is the only moment it can
	// need shrinking.
	s.pruneDPoPProofsLocked(now)

	key := dpopProofKey(proof.Thumbprint, proof.ID)
	if _, spent := s.dpopProofs[key]; spent {
		return ErrDPoPProofReplayed
	}

	// A proof cannot be replayed after its window closes — it is refused on
	// `iat` — so the record only has to outlive the window it was minted for.
	expiresAt := proof.IssuedAt.Add(oidcdomain.DPoPProofLifetime)
	event, err := s.ledger.Append(ctx, oidcdomain.EventDPoPProofSpent, tenantID, actor,
		oidcdomain.DPoPProofSpentPayload{
			ProofID:    proof.ID,
			Thumbprint: proof.Thumbprint,
			TenantID:   tenantID,
			SpentAt:    now.Format(time.RFC3339Nano),
			ExpiresAt:  expiresAt.Format(time.RFC3339Nano),
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	return s.applyDPoPProofSpent(event)
}

// confirmationThumbprint reads `cnf.jkt` out of a token's claims.
func confirmationThumbprint(body map[string]any) (string, bool) {
	confirmation, ok := body[oidcdomain.DPoPConfirmationClaim].(map[string]any)
	if !ok {
		return "", false
	}
	thumbprint, ok := confirmation[oidcdomain.DPoPThumbprintClaim].(string)
	return thumbprint, ok
}

// dpopProofKey scopes a proof identifier to the key that minted it.
func dpopProofKey(thumbprint, id string) string {
	return thumbprint + "\x00" + id
}
