import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Service
type InteractionCookieService struct{}

func (service *InteractionCookieService) Public(response sesame.StandardsResponse) sesame.StandardsResponse {
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
		Headers:         service.headers(response.Headers),
		Body:            body,
	}
}

func (service *InteractionCookieService) Cookie(action sesame.StandardsInteraction) *http.Cookie {
	return &http.Cookie{
		Name:     service.cookieName(),
		Value:    action.InteractionID + service.separator() + action.InteractionSecret,
		Path:     service.cookiePath(),
		MaxAge:   service.lifetimeSeconds(),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

func (service *InteractionCookieService) Handle(value string) OidcInteractionHandle {
	interactionID, secret, _ := strings.Cut(value, service.separator())
	return OidcInteractionHandle{InteractionID: interactionID, InteractionSecret: secret}
}

func (service *InteractionCookieService) headers(engineHeaders map[string]string) map[string]string {
	headers := map[string]string{
		"content-type":           "application/json",
		"x-content-type-options": "nosniff",
	}
	for name, value := range engineHeaders {
		headers[name] = value
	}
	return headers
}

func (service *InteractionCookieService) cookieName() string {
	return "__Secure-sesame_interaction"
}

func (service *InteractionCookieService) cookiePath() string {
	return "/api/v1/oidc"
}

func (service *InteractionCookieService) separator() string {
	return ":"
}

func (service *InteractionCookieService) lifetimeSeconds() int {
	return 900
}
