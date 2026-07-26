package fylo_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	fyloadapter "github.com/d31ma/sesame/internal/adapters/fylo"
	"github.com/d31ma/sesame/internal/adapters/fylo/securityledger"
	identityapp "github.com/d31ma/sesame/internal/application/identity"
	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	tokendomain "github.com/d31ma/sesame/internal/domain/token"
)

// TestRealFYLOAuthorizationCodeSurvivesRestart proves against a real FYLO
// runtime that a spent authorization code stays spent across a process
// restart, and that a code issued before the restart is still redeemable
// exactly once after it.
//
// The in-memory fake cannot prove this: the guarantee is that the redemption
// event is durable and replays into the same projection state.
func TestRealFYLOAuthorizationCodeSurvivesRestart(t *testing.T) {
	if os.Getenv("SESAME_FYLO_INTEGRATION") != "1" {
		t.Skip("set SESAME_FYLO_INTEGRATION=1 to test a real FYLO runtime")
	}
	binary := os.Getenv("FYLO_BINARY")
	if binary == "" {
		binary = "fylo"
	}
	config := fyloadapter.Config{
		Binary:                 binary,
		ExpectedRuntimeVersion: fyloadapter.PhaseOneRuntimeVersion,
		ExpectedBuildTarget:    os.Getenv("SESAME_FYLO_BUILD_TARGET"),
		AllowDevelopmentBuild:  os.Getenv("SESAME_FYLO_ALLOW_DEVELOPMENT") == "1",
	}
	root, err := os.MkdirTemp("", "sesame-oidc-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	config.Root = filepath.Join(root, "db")
	if err := os.Mkdir(config.Root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	const (
		issuer      = "https://id.example"
		redirectURI = "https://app.example/cb"
		verifier    = "sesame-integration-verifier-0123456789-abcdefg"
		password    = "correct horse battery staple"
	)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// One key across both processes, as a deployment key directory would be.
	signingKey, err := tokendomain.NewSigningKey()
	if err != nil {
		t.Fatalf("NewSigningKey() error = %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()

	open := func() (*fyloadapter.Client, *identityapp.Service) {
		t.Helper()
		client, err := fyloadapter.Start(ctx, config)
		if err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		ledger, events, err := securityledger.Open(ctx, client)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		service, err := identityapp.New(ledger, events)
		if err != nil {
			t.Fatalf("identity.New() error = %v", err)
		}
		service.UseSigningKey(signingKey)
		service.UseIssuer(issuer)
		service.UseClock(func() time.Time { return now })
		return client, service
	}

	client, service := open()
	tenant, err := service.Bootstrap(ctx, "acme", "test:integration")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	identifier := principaldomain.Identifier{Namespace: "email", Value: "oidc@example.com"}
	principal, err := service.PrincipalCreate(
		ctx, tenant.Tenant.ID, principaldomain.KindHuman, identifier, "test:integration")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := service.PasswordSet(ctx, principal.ID, password, "test:integration"); err != nil {
		t.Fatalf("PasswordSet() error = %v", err)
	}
	registered, err := service.ClientRegister(ctx, tenant.Tenant.ID, "billing",
		oidcdomain.TypeConfidential, []string{redirectURI}, nil, oidcdomain.AudienceFirstParty, nil, "test:integration")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}

	login := func(service *identityapp.Service) (string, string) {
		t.Helper()
		begun, err := service.AuthenticationBegin(ctx, tenant.Tenant.ID, identifier, "test:integration")
		if err != nil {
			t.Fatalf("AuthenticationBegin() error = %v", err)
		}
		if _, err := service.AuthenticationVerifyPassword(
			ctx, begun.TransactionID, password, "test:integration"); err != nil {
			t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
		}
		issued, err := service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, "test:integration")
		if err != nil {
			t.Fatalf("AuthenticationComplete() error = %v", err)
		}
		return issued.SessionID, issued.Secret
	}

	authorize := func(service *identityapp.Service) identityapp.StartedInteraction {
		t.Helper()
		started, err := service.AuthorizationStart(ctx, identityapp.AuthorizationRequest{
			ClientID:            registered.Client.ID,
			RedirectURI:         redirectURI,
			ResponseType:        oidcdomain.ResponseTypeCode,
			Scopes:              []string{"openid"},
			State:               "csrf",
			Nonce:               "n0",
			CodeChallenge:       challenge,
			CodeChallengeMethod: oidcdomain.ChallengeMethodS256,
		}, "test:integration")
		if err != nil {
			t.Fatalf("AuthorizationStart() error = %v", err)
		}
		return started
	}

	tokenRequest := func(code string) identityapp.TokenRequest {
		return identityapp.TokenRequest{
			GrantType:    oidcdomain.GrantTypeAuthorizationCode,
			Code:         code,
			RedirectURI:  redirectURI,
			ClientID:     registered.Client.ID,
			ClientSecret: registered.Secret,
			CodeVerifier: verifier,
		}
	}

	sessionID, sessionSecret := login(service)

	// One code is spent before the restart; another is issued and left
	// unspent, so the restart has both states to replay.
	spent := authorize(service)
	spentResponse, err := service.AuthorizationComplete(
		ctx, spent.InteractionID, spent.Secret, sessionID, sessionSecret, "test:integration")
	if err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}
	if _, err := service.TokenExchange(ctx, tokenRequest(spentResponse.Code), "test:integration"); err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}

	carried := authorize(service)
	carriedResponse, err := service.AuthorizationComplete(
		ctx, carried.InteractionID, carried.Secret, sessionID, sessionSecret, "test:integration")
	if err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}

	// Kill the process the way a crash would.
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	restarted, replayed := open()
	t.Cleanup(func() { _ = restarted.Close() })

	if _, err := replayed.TokenExchange(ctx, tokenRequest(spentResponse.Code), "test:integration"); !errors.Is(
		err, identityapp.ErrInvalidGrant) {
		t.Fatalf("a spent code was redeemable after restart: %v", err)
	}
	tokens, err := replayed.TokenExchange(ctx, tokenRequest(carriedResponse.Code), "test:integration")
	if err != nil {
		t.Fatalf("a code issued before the restart was not redeemable after it: %v", err)
	}
	claims, _, err := signingKey.Verify(tokens.AccessToken, issuer, registered.Client.ID, now)
	if err != nil || claims.Subject != principal.ID {
		t.Fatalf("access token = %#v, %v", claims, err)
	}
	// And it is single-use on the far side of the restart too.
	if _, err := replayed.TokenExchange(ctx, tokenRequest(carriedResponse.Code), "test:integration"); !errors.Is(
		err, identityapp.ErrInvalidGrant) {
		t.Fatalf("code replay after restart error = %v", err)
	}

	// The client secret survived replay, and the rotated-away one would not.
	if _, err := replayed.ClientAuthenticate(registered.Client.ID, registered.Secret); err != nil {
		t.Fatalf("ClientAuthenticate() after restart error = %v", err)
	}
}

// TestRealFYLORefreshReuseDetectedAcrossRestart proves against a real FYLO
// runtime that a refresh token spent before a restart still triggers reuse
// detection after it. The in-memory fake cannot prove this: the guarantee is
// that the spend event is durable and replays into the same projection.
func TestRealFYLORefreshReuseDetectedAcrossRestart(t *testing.T) {
	if os.Getenv("SESAME_FYLO_INTEGRATION") != "1" {
		t.Skip("set SESAME_FYLO_INTEGRATION=1 to test a real FYLO runtime")
	}
	binary := os.Getenv("FYLO_BINARY")
	if binary == "" {
		binary = "fylo"
	}
	config := fyloadapter.Config{
		Binary:                 binary,
		ExpectedRuntimeVersion: fyloadapter.PhaseOneRuntimeVersion,
		ExpectedBuildTarget:    os.Getenv("SESAME_FYLO_BUILD_TARGET"),
		AllowDevelopmentBuild:  os.Getenv("SESAME_FYLO_ALLOW_DEVELOPMENT") == "1",
	}
	root, err := os.MkdirTemp("", "sesame-refresh-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	config.Root = filepath.Join(root, "db")
	if err := os.Mkdir(config.Root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	const (
		issuer      = "https://id.example"
		redirectURI = "https://app.example/cb"
		verifier    = "sesame-integration-refresh-0123456789-abcdefg"
		password    = "correct horse battery staple"
	)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	signingKey, err := tokendomain.NewSigningKey()
	if err != nil {
		t.Fatalf("NewSigningKey() error = %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()

	open := func() (*fyloadapter.Client, *identityapp.Service) {
		t.Helper()
		client, err := fyloadapter.Start(ctx, config)
		if err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		ledger, events, err := securityledger.Open(ctx, client)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		service, err := identityapp.New(ledger, events)
		if err != nil {
			t.Fatalf("identity.New() error = %v", err)
		}
		service.UseSigningKey(signingKey)
		service.UseIssuer(issuer)
		service.UseClock(func() time.Time { return now })
		return client, service
	}

	client, service := open()
	tenant, err := service.Bootstrap(ctx, "acme", "test:integration")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	identifier := principaldomain.Identifier{Namespace: "email", Value: "offline@example.com"}
	principal, err := service.PrincipalCreate(
		ctx, tenant.Tenant.ID, principaldomain.KindHuman, identifier, "test:integration")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := service.PasswordSet(ctx, principal.ID, password, "test:integration"); err != nil {
		t.Fatalf("PasswordSet() error = %v", err)
	}
	registered, err := service.ClientRegister(ctx, tenant.Tenant.ID, "offline",
		oidcdomain.TypeConfidential, []string{redirectURI},
		[]string{oidcdomain.ScopeOfflineAccess}, oidcdomain.AudienceFirstParty, nil, "test:integration")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}

	begun, err := service.AuthenticationBegin(ctx, tenant.Tenant.ID, identifier, "test:integration")
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := service.AuthenticationVerifyPassword(
		ctx, begun.TransactionID, password, "test:integration"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	session, err := service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, "test:integration")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}
	started, err := service.AuthorizationStart(ctx, identityapp.AuthorizationRequest{
		ClientID:            registered.Client.ID,
		RedirectURI:         redirectURI,
		ResponseType:        oidcdomain.ResponseTypeCode,
		Scopes:              []string{oidcdomain.ScopeOfflineAccess},
		CodeChallenge:       challenge,
		CodeChallengeMethod: oidcdomain.ChallengeMethodS256,
	}, "test:integration")
	if err != nil {
		t.Fatalf("AuthorizationStart() error = %v", err)
	}
	authorized, err := service.AuthorizationComplete(ctx, started.InteractionID, started.Secret,
		session.SessionID, session.Secret, "test:integration")
	if err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}
	tokens, err := service.TokenExchange(ctx, identityapp.TokenRequest{
		GrantType:    oidcdomain.GrantTypeAuthorizationCode,
		Code:         authorized.Code,
		RedirectURI:  redirectURI,
		ClientID:     registered.Client.ID,
		ClientSecret: registered.Secret,
		CodeVerifier: verifier,
	}, "test:integration")
	if err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}
	if tokens.RefreshToken == "" {
		t.Fatal("offline_access produced no refresh token")
	}

	refreshRequest := func(value string) identityapp.TokenRequest {
		return identityapp.TokenRequest{
			GrantType:    oidcdomain.GrantTypeRefreshToken,
			RefreshToken: value,
			ClientID:     registered.Client.ID,
			ClientSecret: registered.Secret,
		}
	}

	stolen := tokens.RefreshToken
	rotated, err := service.TokenExchange(ctx, refreshRequest(stolen), "test:integration")
	if err != nil {
		t.Fatalf("refresh TokenExchange() error = %v", err)
	}

	// Kill the process the way a crash would.
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	restarted, replayed := open()
	t.Cleanup(func() { _ = restarted.Close() })

	// The live successor survived the restart...
	successor, err := replayed.TokenExchange(ctx, refreshRequest(rotated.RefreshToken), "test:integration")
	if err != nil {
		t.Fatalf("the live successor did not survive the restart: %v", err)
	}
	// ...and so did the spent state, so reuse is still detected and still
	// kills the family.
	if _, err := replayed.TokenExchange(ctx, refreshRequest(stolen), "test:integration"); !errors.Is(
		err, identityapp.ErrInvalidGrant) {
		t.Fatalf("a spent refresh token was accepted after restart: %v", err)
	}
	if _, err := replayed.TokenExchange(ctx, refreshRequest(successor.RefreshToken), "test:integration"); !errors.Is(
		err, identityapp.ErrInvalidGrant) {
		t.Fatalf("reuse detection did not kill the family after restart: %v", err)
	}
}

// TestRealFYLOConsentWithdrawalSurvivesRestart proves against a real FYLO
// runtime that a withdrawn consent stays withdrawn across a process restart.
// A withdrawal that a restore quietly undid would re-authorize a client the
// user has already taken back.
func TestRealFYLOConsentWithdrawalSurvivesRestart(t *testing.T) {
	if os.Getenv("SESAME_FYLO_INTEGRATION") != "1" {
		t.Skip("set SESAME_FYLO_INTEGRATION=1 to test a real FYLO runtime")
	}
	binary := os.Getenv("FYLO_BINARY")
	if binary == "" {
		binary = "fylo"
	}
	config := fyloadapter.Config{
		Binary:                 binary,
		ExpectedRuntimeVersion: fyloadapter.PhaseOneRuntimeVersion,
		ExpectedBuildTarget:    os.Getenv("SESAME_FYLO_BUILD_TARGET"),
		AllowDevelopmentBuild:  os.Getenv("SESAME_FYLO_ALLOW_DEVELOPMENT") == "1",
	}
	root, err := os.MkdirTemp("", "sesame-consent-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	config.Root = filepath.Join(root, "db")
	if err := os.Mkdir(config.Root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	const (
		issuer      = "https://id.example"
		redirectURI = "https://app.example/cb"
		verifier    = "sesame-integration-consent-0123456789-abcdefg"
		password    = "correct horse battery staple"
	)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	signingKey, err := tokendomain.NewSigningKey()
	if err != nil {
		t.Fatalf("NewSigningKey() error = %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()

	open := func() (*fyloadapter.Client, *identityapp.Service) {
		t.Helper()
		client, err := fyloadapter.Start(ctx, config)
		if err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		ledger, events, err := securityledger.Open(ctx, client)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		service, err := identityapp.New(ledger, events)
		if err != nil {
			t.Fatalf("identity.New() error = %v", err)
		}
		service.UseSigningKey(signingKey)
		service.UseIssuer(issuer)
		service.UseClock(func() time.Time { return now })
		return client, service
	}

	client, service := open()
	tenant, err := service.Bootstrap(ctx, "acme", "test:integration")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	identifier := principaldomain.Identifier{Namespace: "email", Value: "consent@example.com"}
	principal, err := service.PrincipalCreate(
		ctx, tenant.Tenant.ID, principaldomain.KindHuman, identifier, "test:integration")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := service.PasswordSet(ctx, principal.ID, password, "test:integration"); err != nil {
		t.Fatalf("PasswordSet() error = %v", err)
	}
	registered, err := service.ClientRegister(ctx, tenant.Tenant.ID, "third-party",
		oidcdomain.TypeConfidential, []string{redirectURI}, []string{"profile"}, oidcdomain.AudienceThirdParty, nil, "test:integration")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}

	begun, err := service.AuthenticationBegin(ctx, tenant.Tenant.ID, identifier, "test:integration")
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := service.AuthenticationVerifyPassword(
		ctx, begun.TransactionID, password, "test:integration"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	session, err := service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, "test:integration")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}

	authorize := func(service *identityapp.Service) identityapp.StartedInteraction {
		t.Helper()
		started, err := service.AuthorizationStart(ctx, identityapp.AuthorizationRequest{
			ClientID:            registered.Client.ID,
			RedirectURI:         redirectURI,
			ResponseType:        oidcdomain.ResponseTypeCode,
			Scopes:              []string{"openid", "profile"},
			CodeChallenge:       challenge,
			CodeChallengeMethod: oidcdomain.ChallengeMethodS256,
		}, "test:integration")
		if err != nil {
			t.Fatalf("AuthorizationStart() error = %v", err)
		}
		return started
	}

	// Without consent, no code.
	blocked := authorize(service)
	if _, err := service.AuthorizationComplete(ctx, blocked.InteractionID, blocked.Secret,
		session.SessionID, session.Secret, "test:integration"); !errors.Is(err, identityapp.ErrConsentRequired) {
		t.Fatalf("third-party completion error = %v, want ErrConsentRequired", err)
	}
	if _, err := service.ConsentGrant(ctx, session.SessionID, session.Secret,
		registered.Client.ID, []string{"openid", "profile"}, "test:integration"); err != nil {
		t.Fatalf("ConsentGrant() error = %v", err)
	}
	if _, err := service.AuthorizationComplete(ctx, blocked.InteractionID, blocked.Secret,
		session.SessionID, session.Secret, "test:integration"); err != nil {
		t.Fatalf("AuthorizationComplete() after consent error = %v", err)
	}
	if err := service.ConsentWithdraw(ctx, principal.ID, registered.Client.ID, "test:integration"); err != nil {
		t.Fatalf("ConsentWithdraw() error = %v", err)
	}

	// Kill the process the way a crash would.
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	restarted, replayed := open()
	t.Cleanup(func() { _ = restarted.Close() })

	stored, err := replayed.ConsentGet(principal.ID, registered.Client.ID)
	if err != nil {
		t.Fatalf("ConsentGet() after restart error = %v", err)
	}
	if !stored.Withdrawn {
		t.Fatal("a withdrawn consent came back granted after restart")
	}
	after := authorize(replayed)
	if _, err := replayed.AuthorizationComplete(ctx, after.InteractionID, after.Secret,
		session.SessionID, session.Secret, "test:integration"); !errors.Is(err, identityapp.ErrConsentRequired) {
		t.Fatalf("a withdrawn consent authorized after restart: %v", err)
	}
}
