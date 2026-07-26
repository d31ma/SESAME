package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
)

// offlineFixture registers a client that may hold refresh tokens and runs one
// authorization through to a token set.
func offlineFixture(t *testing.T) (*flowFixture, TokenResponse) {
	t.Helper()

	fixture := newFlowFixture(t)
	ctx := context.Background()

	registered, err := fixture.service.ClientRegister(ctx, fixture.tenantID, "offline",
		oidcdomain.TypeConfidential, []string{flowRedirectURI},
		[]string{"profile", oidcdomain.ScopeOfflineAccess}, oidcdomain.AudienceFirstParty, nil, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}
	fixture.clientID = registered.Client.ID
	fixture.secret = registered.Secret

	started, err := fixture.service.AuthorizationStart(ctx, AuthorizationRequest{
		ClientID:            fixture.clientID,
		RedirectURI:         flowRedirectURI,
		ResponseType:        oidcdomain.ResponseTypeCode,
		Scopes:              []string{"profile", oidcdomain.ScopeOfflineAccess},
		Nonce:               "client-nonce",
		CodeChallenge:       flowChallenge(),
		CodeChallengeMethod: oidcdomain.ChallengeMethodS256,
	}, "test")
	if err != nil {
		t.Fatalf("AuthorizationStart() error = %v", err)
	}
	response, err := fixture.service.AuthorizationComplete(ctx, started.InteractionID, started.Secret,
		fixture.sessionID, fixture.sessionKey, "test")
	if err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}
	tokens, err := fixture.service.TokenExchange(ctx, fixture.tokenRequest(response.Code), "test")
	if err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}
	return fixture, tokens
}

func (f *flowFixture) refreshRequest(refresh, scope string) TokenRequest {
	return TokenRequest{
		GrantType:    oidcdomain.GrantTypeRefreshToken,
		RefreshToken: refresh,
		ClientID:     f.clientID,
		ClientSecret: f.secret,
		Scope:        scope,
	}
}

func TestRefreshTokenIsIssuedOnlyForOfflineAccess(t *testing.T) {
	t.Parallel()

	// The default fixture client has no offline_access, so it gets no
	// refresh token however it asks.
	fixture := newFlowFixture(t)
	ctx := context.Background()
	started := fixture.authorize(t)
	response, err := fixture.service.AuthorizationComplete(ctx, started.InteractionID, started.Secret,
		fixture.sessionID, fixture.sessionKey, "test")
	if err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}
	tokens, err := fixture.service.TokenExchange(ctx, fixture.tokenRequest(response.Code), "test")
	if err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}
	if tokens.RefreshToken != "" {
		t.Fatal("a client without offline_access received a refresh token")
	}

	// Nor can the authorization request add the scope: it is not registered.
	if _, err := fixture.service.AuthorizationStart(ctx, AuthorizationRequest{
		ClientID:            fixture.clientID,
		RedirectURI:         flowRedirectURI,
		ResponseType:        oidcdomain.ResponseTypeCode,
		Scopes:              []string{oidcdomain.ScopeOfflineAccess},
		CodeChallenge:       flowChallenge(),
		CodeChallengeMethod: oidcdomain.ChallengeMethodS256,
	}, "test"); !errors.Is(err, ErrScopeNotAllowed) {
		t.Fatalf("unregistered offline_access error = %v", err)
	}

	_, offlineTokens := offlineFixture(t)
	if offlineTokens.RefreshToken == "" {
		t.Fatal("a client with offline_access received no refresh token")
	}
}

func TestRefreshRotatesOnEveryUse(t *testing.T) {
	t.Parallel()

	fixture, tokens := offlineFixture(t)
	ctx := context.Background()

	first := tokens.RefreshToken
	rotated, err := fixture.service.TokenExchange(ctx, fixture.refreshRequest(first, ""), "test")
	if err != nil {
		t.Fatalf("refresh TokenExchange() error = %v", err)
	}
	if rotated.RefreshToken == "" || rotated.RefreshToken == first {
		t.Fatal("the refresh grant did not rotate the token")
	}
	if rotated.AccessToken == tokens.AccessToken || rotated.Scope != tokens.Scope {
		t.Fatalf("rotated = %#v", rotated)
	}
	// An ID token minted from a refresh attests to no new authentication, so
	// it carries no nonce (OpenID Connect Core section 12.2).
	_, body, err := fixture.signingKey.Verify(rotated.IDToken, flowIssuer, fixture.clientID, fixture.now)
	if err != nil {
		t.Fatalf("refreshed ID token does not verify: %v", err)
	}
	if _, present := body["nonce"]; present {
		t.Fatalf("a refreshed ID token carries a nonce: %#v", body)
	}

	// The successor works, and rotation continues.
	third, err := fixture.service.TokenExchange(ctx, fixture.refreshRequest(rotated.RefreshToken, ""), "test")
	if err != nil {
		t.Fatalf("second refresh error = %v", err)
	}
	if third.RefreshToken == rotated.RefreshToken {
		t.Fatal("the second refresh did not rotate")
	}
}

// TestRefreshReuseKillsTheFamily is the reuse-detection guarantee: two
// parties holding tokens from one family means one of them stole a token, and
// SESAME cannot tell which, so neither keeps the grant.
func TestRefreshReuseKillsTheFamily(t *testing.T) {
	t.Parallel()

	fixture, tokens := offlineFixture(t)
	ctx := context.Background()

	stolen := tokens.RefreshToken
	legitimate, err := fixture.service.TokenExchange(ctx, fixture.refreshRequest(stolen, ""), "test")
	if err != nil {
		t.Fatalf("refresh TokenExchange() error = %v", err)
	}

	// The thief presents the copy it took before the rotation.
	if _, err := fixture.service.TokenExchange(ctx, fixture.refreshRequest(stolen, ""), "test"); !errors.Is(
		err, ErrInvalidGrant) {
		t.Fatalf("reused token error = %v, want ErrInvalidGrant", err)
	}
	// The legitimate client's live successor dies with the family. That is
	// the correct cost: the alternative leaves the thief with a live grant.
	if _, err := fixture.service.TokenExchange(ctx, fixture.refreshRequest(legitimate.RefreshToken, ""), "test"); !errors.Is(
		err, ErrInvalidGrant) {
		t.Fatalf("successor after reuse error = %v, want ErrInvalidGrant", err)
	}

	familyID := fixture.onlyFamily(t)
	family, err := fixture.service.RefreshFamilyGet(familyID)
	if err != nil {
		t.Fatalf("RefreshFamilyGet() error = %v", err)
	}
	if !family.Revoked || family.Reason != oidcdomain.RevokedReasonReuse {
		t.Fatalf("family = %#v", family)
	}
}

func (f *flowFixture) onlyFamily(t *testing.T) string {
	t.Helper()

	f.service.mu.Lock()
	defer f.service.mu.Unlock()
	if len(f.service.refreshFamilies) != 1 {
		t.Fatalf("expected exactly one refresh family, got %d", len(f.service.refreshFamilies))
	}
	for id := range f.service.refreshFamilies {
		return id
	}
	return ""
}

func TestRefreshScopesNarrowButNeverWiden(t *testing.T) {
	t.Parallel()

	fixture, tokens := offlineFixture(t)
	ctx := context.Background()

	narrowed, err := fixture.service.TokenExchange(ctx,
		fixture.refreshRequest(tokens.RefreshToken, "openid"), "test")
	if err != nil {
		t.Fatalf("narrowing refresh error = %v", err)
	}
	if narrowed.Scope != "openid" {
		t.Fatalf("narrowed scope = %q", narrowed.Scope)
	}
	// Narrowing away offline_access ends the family's ability to refresh,
	// which is the honest consequence of the client asking for less.
	if narrowed.RefreshToken != "" {
		t.Fatal("a refresh that dropped offline_access still issued a refresh token")
	}

	widening, held := offlineFixture(t)
	if _, err := widening.service.TokenExchange(ctx,
		widening.refreshRequest(held.RefreshToken, "admin"), "test"); !errors.Is(err, ErrScopeNotAllowed) {
		t.Fatalf("a refresh widened its scopes: %v", err)
	}
	// A refused widening does not spend the token.
	if _, err := widening.service.TokenExchange(ctx, widening.refreshRequest(held.RefreshToken, ""), "test"); err != nil {
		t.Fatalf("refresh after a refused widening error = %v", err)
	}
}

// TestExpiredSessionDoesNotEndTheRefreshGrant pins the distinction that makes
// offline_access mean anything: a session that merely ran out of time is not
// a revocation, and access "while the user is away" is the whole point.
func TestExpiredSessionDoesNotEndTheRefreshGrant(t *testing.T) {
	t.Parallel()

	fixture, tokens := offlineFixture(t)
	ctx := context.Background()

	// The browser session is long gone.
	fixture.now = fixture.now.Add(2 * time.Hour)
	if _, err := fixture.service.SessionVerify(fixture.sessionID, fixture.sessionKey); !errors.Is(
		err, ErrSessionInactive) {
		t.Fatalf("the session has not expired: %v", err)
	}

	refreshed, err := fixture.service.TokenExchange(ctx, fixture.refreshRequest(tokens.RefreshToken, ""), "test")
	if err != nil {
		t.Fatalf("refresh after session expiry error = %v", err)
	}
	if refreshed.AccessToken == "" {
		t.Fatal("refresh issued no access token")
	}

	// Revocation still bites, because that is a deliberate act.
	if err := fixture.service.SessionRevoke(ctx, fixture.sessionID, "signed out", "test"); err != nil {
		t.Fatalf("SessionRevoke() error = %v", err)
	}
	if _, err := fixture.service.TokenExchange(ctx,
		fixture.refreshRequest(refreshed.RefreshToken, ""), "test"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("refresh after session revocation error = %v", err)
	}
}

func TestRefreshRequiresTheOwningClientAndLiveAuthentication(t *testing.T) {
	t.Parallel()

	fixture, tokens := offlineFixture(t)
	ctx := context.Background()

	other, err := fixture.service.ClientRegister(ctx, fixture.tenantID, "other",
		oidcdomain.TypeConfidential, []string{flowRedirectURI},
		[]string{oidcdomain.ScopeOfflineAccess}, oidcdomain.AudienceFirstParty, nil, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}

	cases := map[string]func(TokenRequest) TokenRequest{
		"another client": func(r TokenRequest) TokenRequest {
			r.ClientID = other.Client.ID
			r.ClientSecret = other.Secret
			return r
		},
		"wrong client secret": func(r TokenRequest) TokenRequest {
			r.ClientSecret = "hunter2"
			return r
		},
		"forged token": func(r TokenRequest) TokenRequest {
			id, _, _ := strings.Cut(r.RefreshToken, ".")
			r.RefreshToken = id + ".not-the-secret"
			return r
		},
		"no handle": func(r TokenRequest) TokenRequest {
			r.RefreshToken = "nonsense"
			return r
		},
		"unknown token": func(r TokenRequest) TokenRequest {
			r.RefreshToken = "rft_00000000000000000000000000000000.x"
			return r
		},
	}
	for label, mutate := range cases {
		if _, err := fixture.service.TokenExchange(ctx,
			mutate(fixture.refreshRequest(tokens.RefreshToken, "")), "test"); err == nil {
			t.Fatalf("refresh accepted %s", label)
		}
	}
	// None of those spent the token: the genuine request still works.
	if _, err := fixture.service.TokenExchange(ctx, fixture.refreshRequest(tokens.RefreshToken, ""), "test"); err != nil {
		t.Fatalf("refresh after failed attempts error = %v", err)
	}
}

func TestRevokedSessionEndsTheRefreshGrant(t *testing.T) {
	t.Parallel()

	fixture, tokens := offlineFixture(t)
	ctx := context.Background()

	if err := fixture.service.SessionRevoke(ctx, fixture.sessionID, "signed out", "test"); err != nil {
		t.Fatalf("SessionRevoke() error = %v", err)
	}
	// A refresh token outliving the authentication behind it would make
	// session revocation cosmetic.
	if _, err := fixture.service.TokenExchange(ctx, fixture.refreshRequest(tokens.RefreshToken, ""), "test"); !errors.Is(
		err, ErrInvalidGrant) {
		t.Fatalf("refresh after session revocation error = %v", err)
	}
}

func TestRefreshExpiryAndFamilyCeiling(t *testing.T) {
	t.Parallel()

	fixture, tokens := offlineFixture(t)
	ctx := context.Background()

	fixture.now = fixture.now.Add(oidcdomain.RefreshLifetime + time.Second)
	if _, err := fixture.service.TokenExchange(ctx, fixture.refreshRequest(tokens.RefreshToken, ""), "test"); !errors.Is(
		err, ErrInvalidGrant) {
		t.Fatalf("expired refresh token error = %v", err)
	}

	// Rotation must not extend the family past its absolute ceiling. Each
	// step is well inside a single token's lifetime, so only the ceiling can
	// be what eventually stops it.
	ceiling, current := offlineFixture(t)
	held := current.RefreshToken
	const step = 20 * 24 * time.Hour
	for elapsed := step; elapsed < oidcdomain.RefreshFamilyLifetime; elapsed += step {
		ceiling.now = ceiling.now.Add(step)
		next, err := ceiling.service.TokenExchange(ctx, ceiling.refreshRequest(held, ""), "test")
		if err != nil {
			t.Fatalf("rotation at %s error = %v", elapsed, err)
		}
		held = next.RefreshToken
	}
	ceiling.now = ceiling.now.Add(oidcdomain.RefreshFamilyLifetime)
	if _, err := ceiling.service.TokenExchange(ctx, ceiling.refreshRequest(held, ""), "test"); !errors.Is(
		err, ErrInvalidGrant) {
		t.Fatalf("rotation outlived the family ceiling: %v", err)
	}
}

func TestRefreshFamilyRevokeIsDurableAndIdempotent(t *testing.T) {
	t.Parallel()

	fixture, tokens := offlineFixture(t)
	ctx := context.Background()
	familyID := fixture.onlyFamily(t)

	if err := fixture.service.RefreshFamilyRevoke(ctx, familyID, "", "test"); err != nil {
		t.Fatalf("RefreshFamilyRevoke() error = %v", err)
	}
	if err := fixture.service.RefreshFamilyRevoke(ctx, familyID, "", "test"); err != nil {
		t.Fatalf("repeated RefreshFamilyRevoke() error = %v", err)
	}
	if _, err := fixture.service.TokenExchange(ctx, fixture.refreshRequest(tokens.RefreshToken, ""), "test"); !errors.Is(
		err, ErrInvalidGrant) {
		t.Fatalf("refresh after family revocation error = %v", err)
	}
	if err := fixture.service.RefreshFamilyRevoke(ctx, "rfm_00000000000000000000000000000000", "", "test"); !errors.Is(
		err, ErrRefreshFamilyNotFound) {
		t.Fatalf("RefreshFamilyRevoke on an unknown family error = %v", err)
	}
}

// TestRefreshStateSurvivesSnapshotAndReplay is the regression guard for a
// snapshot that forgets the refresh projection: a spent token must come back
// spent, or a restore would silently disable reuse detection.
func TestRefreshStateSurvivesSnapshotAndReplay(t *testing.T) {
	t.Parallel()

	fixture, tokens := offlineFixture(t)
	snapshots := &memorySnapshots{}
	fixture.service.UseSnapshots(snapshots)
	ctx := context.Background()

	spent := tokens.RefreshToken
	rotated, err := fixture.service.TokenExchange(ctx, fixture.refreshRequest(spent, ""), "test")
	if err != nil {
		t.Fatalf("refresh TokenExchange() error = %v", err)
	}

	rebuilt := map[string]*Service{}
	replayed, err := New(&memoryLedger{}, fixture.ledger.events)
	if err != nil {
		t.Fatalf("replay New() error = %v", err)
	}
	rebuilt["replay"] = replayed
	seeded, err := NewFromSnapshot(&memoryLedger{}, snapshots.states[len(snapshots.states)-1], nil)
	if err != nil {
		t.Fatalf("NewFromSnapshot() error = %v", err)
	}
	rebuilt["snapshot"] = seeded

	for kind, restored := range rebuilt {
		restored.UseSigningKey(fixture.signingKey)
		restored.UseIssuer(flowIssuer)
		restored.UseClock(func() time.Time { return fixture.now })

		// The live successor still works after the restart...
		next, err := restored.TokenExchange(ctx, fixture.refreshRequest(rotated.RefreshToken, ""), "test")
		if err != nil {
			t.Fatalf("%s: the live successor did not survive: %v", kind, err)
		}
		// ...and the token spent before the restart still triggers reuse
		// detection, killing the family.
		if _, err := restored.TokenExchange(ctx, fixture.refreshRequest(spent, ""), "test"); !errors.Is(
			err, ErrInvalidGrant) {
			t.Fatalf("%s: a spent token was accepted after restore: %v", kind, err)
		}
		if _, err := restored.TokenExchange(ctx, fixture.refreshRequest(next.RefreshToken, ""), "test"); !errors.Is(
			err, ErrInvalidGrant) {
			t.Fatalf("%s: reuse detection did not kill the family after restore: %v", kind, err)
		}
	}

	// No refresh token reaches the snapshot or the ledger in usable form.
	encoded := string(snapshots.states[len(snapshots.states)-1])
	for _, value := range []string{spent, rotated.RefreshToken} {
		secret := value[strings.Index(value, ".")+1:]
		if strings.Contains(encoded, secret) {
			t.Fatal("the snapshot carries a plaintext refresh token")
		}
		for _, event := range fixture.ledger.events {
			if strings.Contains(string(event.Payload), secret) {
				t.Fatalf("event %s carries a plaintext refresh token", event.Type)
			}
		}
	}
}
