package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
)

// thirdPartyFixture registers a client that needs the user's agreement and
// starts one authorization for it.
func thirdPartyFixture(t *testing.T) (*flowFixture, StartedInteraction) {
	t.Helper()

	fixture := newFlowFixture(t)
	ctx := context.Background()

	registered, err := fixture.service.ClientRegister(ctx, fixture.tenantID, "third-party",
		oidcdomain.TypeConfidential, []string{flowRedirectURI},
		[]string{"profile", oidcdomain.ScopeOfflineAccess}, oidcdomain.AudienceThirdParty, nil, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}
	fixture.clientID = registered.Client.ID
	fixture.secret = registered.Secret
	return fixture, fixture.authorize(t)
}

// TestThirdPartyClientCannotIssueACodeWithoutConsent is the gap this slice
// closes: authentication proves who the user is, not that they agreed to this
// client holding these scopes.
func TestThirdPartyClientCannotIssueACodeWithoutConsent(t *testing.T) {
	t.Parallel()

	fixture, started := thirdPartyFixture(t)
	ctx := context.Background()

	if _, err := fixture.service.AuthorizationComplete(ctx, started.InteractionID, started.Secret,
		fixture.sessionID, fixture.sessionKey, "test"); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("a third-party client issued a code without consent: %v", err)
	}

	// The interaction is not spent by the refusal: the host is expected to
	// show a consent screen and come back to the same interaction.
	consent, err := fixture.service.ConsentGrant(ctx, fixture.sessionID, fixture.sessionKey,
		fixture.clientID, []string{"openid", "profile"}, "test")
	if err != nil {
		t.Fatalf("ConsentGrant() error = %v", err)
	}
	if consent.PrincipalID != fixture.principalID || strings.Join(consent.Scopes, " ") != "openid profile" {
		t.Fatalf("consent = %#v", consent)
	}

	response, err := fixture.service.AuthorizationComplete(ctx, started.InteractionID, started.Secret,
		fixture.sessionID, fixture.sessionKey, "test")
	if err != nil {
		t.Fatalf("AuthorizationComplete() after consent error = %v", err)
	}
	if response.Code == "" {
		t.Fatal("no code was issued after consent")
	}
}

// TestFirstPartyClientNeedsNoConsent pins the other half: where the
// administrator who registered the client and the organization running the
// account are the same party, there is nobody separate to ask.
func TestFirstPartyClientNeedsNoConsent(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	ctx := context.Background()
	started := fixture.authorize(t)

	if _, err := fixture.service.AuthorizationComplete(ctx, started.InteractionID, started.Secret,
		fixture.sessionID, fixture.sessionKey, "test"); err != nil {
		t.Fatalf("a first-party client was blocked on consent: %v", err)
	}
}

// TestConsentIsCheckedAgainstRequestedScopes is what makes consent mean
// something: agreeing to one scope set does not authorize a later request for
// a wider one.
func TestConsentIsCheckedAgainstRequestedScopes(t *testing.T) {
	t.Parallel()

	fixture, _ := thirdPartyFixture(t)
	ctx := context.Background()

	if _, err := fixture.service.ConsentGrant(ctx, fixture.sessionID, fixture.sessionKey,
		fixture.clientID, []string{"openid"}, "test"); err != nil {
		t.Fatalf("ConsentGrant() error = %v", err)
	}

	// The fixture's authorize() asks for openid+profile, which is more than
	// was agreed.
	wider := fixture.authorize(t)
	if _, err := fixture.service.AuthorizationComplete(ctx, wider.InteractionID, wider.Secret,
		fixture.sessionID, fixture.sessionKey, "test"); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("a wider request rode on a narrower consent: %v", err)
	}

	// Agreeing to the extra scope merges rather than replacing.
	merged, err := fixture.service.ConsentGrant(ctx, fixture.sessionID, fixture.sessionKey,
		fixture.clientID, []string{"profile"}, "test")
	if err != nil {
		t.Fatalf("ConsentGrant() error = %v", err)
	}
	if strings.Join(merged.Scopes, " ") != "openid profile" {
		t.Fatalf("merged consent = %#v", merged.Scopes)
	}
	if _, err := fixture.service.AuthorizationComplete(ctx, wider.InteractionID, wider.Secret,
		fixture.sessionID, fixture.sessionKey, "test"); err != nil {
		t.Fatalf("AuthorizationComplete() after merged consent error = %v", err)
	}
}

func TestConsentRequiresTheAgreeingPrincipalsSession(t *testing.T) {
	t.Parallel()

	fixture, _ := thirdPartyFixture(t)
	ctx := context.Background()

	// A caller cannot consent on somebody else's behalf: the session is what
	// establishes who is agreeing.
	if _, err := fixture.service.ConsentGrant(ctx, fixture.sessionID, "wrong",
		fixture.clientID, []string{"openid"}, "test"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("consent with a wrong session secret error = %v", err)
	}

	// Nor across a tenant boundary.
	other, err := fixture.service.Bootstrap(ctx, "other", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	stranger, err := fixture.service.PrincipalCreate(ctx, other.Tenant.ID, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "stranger@example.com"}, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := fixture.service.PasswordSet(ctx, stranger.ID, flowPassword, "test"); err != nil {
		t.Fatalf("PasswordSet() error = %v", err)
	}
	begun, _ := fixture.service.AuthenticationBegin(ctx, other.Tenant.ID,
		principaldomain.Identifier{Namespace: "email", Value: "stranger@example.com"}, "test")
	if _, err := fixture.service.AuthenticationVerifyPassword(ctx, begun.TransactionID, flowPassword, "test"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	crossTenant, err := fixture.service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, "test")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}
	if _, err := fixture.service.ConsentGrant(ctx, crossTenant.SessionID, crossTenant.Secret,
		fixture.clientID, []string{"openid"}, "test"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("cross-tenant consent error = %v", err)
	}

	// A user cannot agree to more than the client is registered for: consent
	// narrows an administrator's decision, it never widens it.
	if _, err := fixture.service.ConsentGrant(ctx, fixture.sessionID, fixture.sessionKey,
		fixture.clientID, []string{"admin"}, "test"); !errors.Is(err, ErrScopeNotAllowed) {
		t.Fatalf("consent to an unregistered scope error = %v", err)
	}
}

// TestConsentWithdrawalStopsLiveTokens is the difference between a withdrawal
// and a withdrawal in name only: the client must also stop refreshing.
func TestConsentWithdrawalStopsLiveTokens(t *testing.T) {
	t.Parallel()

	fixture, started := thirdPartyFixture(t)
	ctx := context.Background()

	if _, err := fixture.service.ConsentGrant(ctx, fixture.sessionID, fixture.sessionKey,
		fixture.clientID, []string{"openid", "profile", oidcdomain.ScopeOfflineAccess}, "test"); err != nil {
		t.Fatalf("ConsentGrant() error = %v", err)
	}
	// Re-authorize asking for offline_access so a refresh token exists.
	offline, err := fixture.service.AuthorizationStart(ctx, AuthorizationRequest{
		ClientID:            fixture.clientID,
		RedirectURI:         flowRedirectURI,
		ResponseType:        oidcdomain.ResponseTypeCode,
		Scopes:              []string{"profile", oidcdomain.ScopeOfflineAccess},
		CodeChallenge:       flowChallenge(),
		CodeChallengeMethod: oidcdomain.ChallengeMethodS256,
	}, "test")
	if err != nil {
		t.Fatalf("AuthorizationStart() error = %v", err)
	}
	response, err := fixture.service.AuthorizationComplete(ctx, offline.InteractionID, offline.Secret,
		fixture.sessionID, fixture.sessionKey, "test")
	if err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}
	tokens, err := fixture.service.TokenExchange(ctx, fixture.tokenRequest(response.Code), "test")
	if err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}
	if tokens.RefreshToken == "" {
		t.Fatal("offline_access produced no refresh token")
	}

	if err := fixture.service.ConsentWithdraw(ctx, fixture.principalID, fixture.clientID, "test"); err != nil {
		t.Fatalf("ConsentWithdraw() error = %v", err)
	}
	if err := fixture.service.ConsentWithdraw(ctx, fixture.principalID, fixture.clientID, "test"); err != nil {
		t.Fatalf("repeated ConsentWithdraw() error = %v", err)
	}

	// The live refresh token dies with the agreement it rested on.
	if _, err := fixture.service.TokenExchange(ctx,
		fixture.refreshRequest(tokens.RefreshToken, ""), "test"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("a withdrawn consent still refreshed: %v", err)
	}
	// And no new code is issued either.
	if _, err := fixture.service.AuthorizationComplete(ctx, started.InteractionID, started.Secret,
		fixture.sessionID, fixture.sessionKey, "test"); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("a withdrawn consent still authorized: %v", err)
	}

	if err := fixture.service.ConsentWithdraw(ctx, fixture.principalID,
		"cli_00000000000000000000000000000000", "test"); !errors.Is(err, ErrConsentNotFound) {
		t.Fatalf("ConsentWithdraw on an unknown consent error = %v", err)
	}
}

// TestConsentSurvivesSnapshotAndReplay is the regression guard for a snapshot
// that forgets the consent projection. A withdrawn agreement coming back
// granted would re-authorize a client the user has already taken back.
func TestConsentSurvivesSnapshotAndReplay(t *testing.T) {
	t.Parallel()

	fixture, _ := thirdPartyFixture(t)
	snapshots := &memorySnapshots{}
	fixture.service.UseSnapshots(snapshots)
	ctx := context.Background()

	live, err := fixture.service.ClientRegister(ctx, fixture.tenantID, "still-agreed",
		oidcdomain.TypeConfidential, []string{flowRedirectURI},
		[]string{"profile"}, oidcdomain.AudienceThirdParty, nil, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}
	if _, err := fixture.service.ConsentGrant(ctx, fixture.sessionID, fixture.sessionKey,
		live.Client.ID, []string{"openid", "profile"}, "test"); err != nil {
		t.Fatalf("ConsentGrant() error = %v", err)
	}
	if _, err := fixture.service.ConsentGrant(ctx, fixture.sessionID, fixture.sessionKey,
		fixture.clientID, []string{"openid", "profile"}, "test"); err != nil {
		t.Fatalf("ConsentGrant() error = %v", err)
	}
	if err := fixture.service.ConsentWithdraw(ctx, fixture.principalID, fixture.clientID, "test"); err != nil {
		t.Fatalf("ConsentWithdraw() error = %v", err)
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
		withdrawn, err := restored.ConsentGet(fixture.principalID, fixture.clientID)
		if err != nil {
			t.Fatalf("%s: ConsentGet() error = %v", kind, err)
		}
		if !withdrawn.Withdrawn {
			t.Fatalf("%s: a withdrawn consent came back granted", kind)
		}
		standing, err := restored.ConsentGet(fixture.principalID, live.Client.ID)
		if err != nil {
			t.Fatalf("%s: ConsentGet() error = %v", kind, err)
		}
		if standing.Withdrawn || strings.Join(standing.Scopes, " ") != "openid profile" {
			t.Fatalf("%s: standing consent = %#v", kind, standing)
		}
	}
}
