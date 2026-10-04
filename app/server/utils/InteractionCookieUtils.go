import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/d31ma/sesame/app/server/packages/sesame"
)

type InteractionCookieUtils struct{}

func (InteractionCookieUtils) WithoutSecret(response sesame.StandardsResponse) sesame.StandardsResponse {
	action := *response.Action
	body, _ := json.Marshal(OidcInteractionStarted{
		InteractionID: action.InteractionID,
		ClientID:      action.ClientID,
		ClientName:    action.ClientName,
		Scopes:        action.Scopes,
		ExpiresAt:     action.ExpiresAt,
	})
	return sesame.StandardsResponse{
		ContractVersion: response.ContractVersion,
		Status:          response.Status,
		Headers:         InteractionCookieUtils{}.headers(response.Headers),
		Body:            body,
	}
}

func (InteractionCookieUtils) Cookie(action sesame.StandardsInteraction) *http.Cookie {
	return &http.Cookie{
		Name:     InteractionCookieUtils{}.cookieName(),
		Value:    action.InteractionID + InteractionCookieUtils{}.separator() + action.InteractionSecret,
		Path:     InteractionCookieUtils{}.cookiePath(),
		MaxAge:   InteractionCookieUtils{}.lifetimeSeconds(),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

func (InteractionCookieUtils) Handle(value string) OidcInteractionHandle {
	interactionID, secret, _ := strings.Cut(value, InteractionCookieUtils{}.separator())
	return OidcInteractionHandle{InteractionID: interactionID, InteractionSecret: secret}
}

func (InteractionCookieUtils) headers(engineHeaders map[string]string) map[string]string {
	headers := map[string]string{
		"content-type":           "application/json",
		"x-content-type-options": "nosniff",
	}
	for name, value := range engineHeaders {
		headers[name] = value
	}
	return headers
}

func (InteractionCookieUtils) cookieName() string {
	return "__Secure-sesame_interaction"
}

func (InteractionCookieUtils) cookiePath() string {
	return "/api/v1/oidc"
}

func (InteractionCookieUtils) separator() string {
	return ":"
}

func (InteractionCookieUtils) lifetimeSeconds() int {
	return 900
}
