package machine

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/d31ma/sesame/internal/application/identity"
	"github.com/d31ma/sesame/internal/application/system"
	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	"github.com/d31ma/sesame/internal/platform/buildinfo"
)

const unknownInteractionID = "int_00000000000000000000000000000000"

type heldInteractionFixture struct {
	processor *Processor
	started   identity.StartedInteraction
	advance   func(time.Duration)
}

func newHeldInteractionFixture(t *testing.T) heldInteractionFixture {
	t.Helper()
	service, err := identity.New(&memoryLedger{}, nil)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	service.UseClock(func() time.Time { return now })
	processor := New(system.New(buildinfo.New("", "", "")), service)

	ctx := context.Background()
	tenant, err := service.Bootstrap(ctx, "acme", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	registered, err := service.ClientRegister(ctx, tenant.Tenant.ID, "billing", "confidential",
		[]string{edgeRedirect}, nil, oidcdomain.AudienceFirstParty, nil, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}
	authorized := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"az","operation":"oidc.authorize","parameters":{"client_id":"`+registered.Client.ID+
			`","redirect_uri":"`+edgeRedirect+`","response_type":"code","scopes":["openid"],"code_challenge":"`+
			edgeChallenge()+`","code_challenge_method":"S256"}}`,
	)[0]
	if !authorized.OK {
		t.Fatalf("oidc.authorize response = %#v", authorized)
	}
	var started identity.StartedInteraction
	if err := json.Unmarshal(mustMarshal(t, authorized.Result), &started); err != nil {
		t.Fatalf("decode interaction: %v", err)
	}
	return heldInteractionFixture{
		processor: processor,
		started:   started,
		advance:   func(step time.Duration) { now = now.Add(step) },
	}
}

func heldInteractionGet(t *testing.T, interactionID, secret string) string {
	t.Helper()
	return `{"protocol_version":"1","request_id":"same","operation":"oidc.interaction_get","parameters":{"interaction_id":` +
		jsonString(t, interactionID) + `,"interaction_secret":` + jsonString(t, secret) + `}}`
}

func TestInteractionGetWithSecretAnswersEveryWrongHandleAsUnknown(t *testing.T) {
	t.Parallel()
	fixture := newHeldInteractionFixture(t)
	id, secret := fixture.started.InteractionID, fixture.started.Secret
	unknown := string(mustMarshal(t, runRequests(t, fixture.processor, heldInteractionGet(t, unknownInteractionID, secret))[0]))

	wrongHandles := map[string][2]string{
		"wrong secret":               {id, "not-the-secret"},
		"empty secret":               {id, ""},
		"empty handle":               {"", ""},
		"garbage handle":             {"garbage", ""},
		"whole cookie as the handle": {id + ":" + secret, ""},
		"url-encoded separator":      {id + "%3A" + secret, ""},
		"truncated handle":           {id[:len(id)-1], secret},
		"handle with non-hex digits": {oidcdomain.InteractionIDPrefix + strings.Repeat("z", 32), secret},
		"handle without its prefix":  {strings.TrimPrefix(id, oidcdomain.InteractionIDPrefix), secret},
	}
	for attempt := 0; attempt < 20; attempt++ {
		for name, handle := range wrongHandles {
			answer := runRequests(t, fixture.processor, heldInteractionGet(t, handle[0], handle[1]))[0]
			if got := string(mustMarshal(t, answer)); got != unknown {
				t.Fatalf("attempt %d, %s: oidc.interaction_get = %s, want the unknown answer %s", attempt, name, got, unknown)
			}
		}
	}
}

func TestInteractionGetWithSecretAfterExpiry(t *testing.T) {
	t.Parallel()
	fixture := newHeldInteractionFixture(t)
	id, secret := fixture.started.InteractionID, fixture.started.Secret
	unknown := string(mustMarshal(t, runRequests(t, fixture.processor, heldInteractionGet(t, unknownInteractionID, secret))[0]))

	for _, step := range []time.Duration{oidcdomain.InteractionLifetime - time.Nanosecond, time.Nanosecond, time.Nanosecond, time.Hour} {
		fixture.advance(step)
		answers := runRequests(t, fixture.processor,
			heldInteractionGet(t, id, "not-the-secret"),
			heldInteractionGet(t, id, secret),
		)
		if got := string(mustMarshal(t, answers[0])); got != unknown {
			t.Fatalf("wrong secret after %v = %s, want the unknown answer %s", step, got, unknown)
		}
		if !answers[1].OK {
			t.Fatalf("holder after %v = %#v, want the record", step, answers[1])
		}
	}
}

func TestInteractionGetWithoutSecretKeepsItsValidationAnswer(t *testing.T) {
	t.Parallel()
	fixture := newHeldInteractionFixture(t)
	answers := runRequests(t, fixture.processor,
		`{"protocol_version":"1","request_id":"op-1","operation":"oidc.interaction_get","parameters":{"interaction_id":"garbage"}}`,
		`{"protocol_version":"1","request_id":"op-2","operation":"oidc.interaction_get","parameters":{"interaction_id":"`+unknownInteractionID+`"}}`,
	)
	want := `{"protocol_version":"1","request_id":"op-1","ok":false,"error":{"code":"invalid_request",` +
		`"message":"interaction ID must be int_ followed by 32 hex characters","retryable":false}}`
	if got := string(mustMarshal(t, answers[0])); got != want {
		t.Fatalf("malformed operator lookup = %s, want %s", got, want)
	}
	if answers[1].OK || answers[1].Error.Code != ErrorInteractionNotFound {
		t.Fatalf("unknown operator lookup = %#v, want %s", answers[1], ErrorInteractionNotFound)
	}
}

func TestHeldInteractionErrorResponseHidesAnUnexpectedFailure(t *testing.T) {
	t.Parallel()
	answer := heldInteractionErrorResponse("held", errors.New("ledger replay detail that must not leak"))
	if answer.OK || answer.Error.Code != ErrorInternal || strings.Contains(answer.Error.Message, "leak") {
		t.Fatalf("unexpected failure = %#v, want %s without its text", answer, ErrorInternal)
	}
	notFound := heldInteractionErrorResponse("held", identity.ErrInteractionNotFound)
	if notFound.OK || notFound.Error.Code != ErrorInteractionNotFound {
		t.Fatalf("unknown interaction = %#v, want %s", notFound, ErrorInteractionNotFound)
	}
}

func TestInteractionCompleteAnswersEveryMalformedHandleAsUnknown(t *testing.T) {
	t.Parallel()
	fixture := newHeldInteractionFixture(t)
	id, secret := fixture.started.InteractionID, fixture.started.Secret
	complete := func(interactionID, interactionSecret string) string {
		return `{"protocol_version":"1","request_id":"same","operation":"oidc.interaction_complete","parameters":{"interaction_id":` +
			jsonString(t, interactionID) + `,"interaction_secret":` + jsonString(t, interactionSecret) +
			`,"session_id":"ses_00000000000000000000000000000000","session_secret":"not-a-session"}}`
	}
	unknown := string(mustMarshal(t, runRequests(t, fixture.processor, complete(unknownInteractionID, secret))[0]))
	if !strings.Contains(unknown, ErrorInteractionNotFound) {
		t.Fatalf("unknown interaction = %s, want %s", unknown, ErrorInteractionNotFound)
	}
	for name, handle := range map[string][2]string{
		"wrong secret":               {id, "not-the-secret"},
		"empty handle":               {"", ""},
		"garbage handle":             {"garbage", ""},
		"whole cookie as the handle": {id + ":" + secret, ""},
		"url-encoded separator":      {id + "%3A" + secret, ""},
		"handle with non-hex digits": {oidcdomain.InteractionIDPrefix + strings.Repeat("z", 32), secret},
	} {
		answer := runRequests(t, fixture.processor, complete(handle[0], handle[1]))[0]
		if got := string(mustMarshal(t, answer)); got != unknown {
			t.Fatalf("%s: oidc.interaction_complete = %s, want the unknown answer %s", name, got, unknown)
		}
	}
}
