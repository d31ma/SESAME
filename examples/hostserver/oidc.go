package main

import (
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/d31ma/sesame/clients/go/sesame"
)

// This file is the host side of SESAME's external interaction contract.
//
// SESAME opens no port and renders no page. Everything here — the routes,
// the cookie, the form — belongs to the host application. The engine decides;
// the host only carries bytes between a browser and the engine.
//
// The login form below is a demonstration, not a product UI. A real host
// would render its own branded page, add rate limiting and bot resistance,
// and offer MFA. What must not change is the shape: /authorize validates
// before anything is shown, the interaction secret never reaches the browser
// as a URL parameter, and the redirect target comes from the engine.

// interactionCookie carries the interaction handle across the login page. It
// is HttpOnly and short-lived because it is bearer-equivalent for the
// duration of one login.
const (
	interactionCookie = "sesame_interaction"
	// sessionCookieName carries the authenticated session across the consent
	// round trip, which is a second request the user makes after logging in.
	sessionCookieName = "sesame_session"
)

var consentPage = template.Must(template.New("consent").Parse(`<!doctype html>
<title>Authorize {{.ClientName}}</title>
<h1>{{.ClientName}} wants access to your account</h1>
<ul>{{range .Scopes}}<li>{{.}}</li>{{end}}</ul>
<form method="post" action="/consent">
  <button name="decision" value="allow" type="submit">Allow</button>
  <button name="decision" value="deny" type="submit">Deny</button>
</form>`))

var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<title>Sign in</title>
<h1>Sign in to {{.ClientName}}</h1>
{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}
<form method="post" action="/login">
  <label>Email <input name="email" type="email" autocomplete="username" required></label>
  <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
  <label>Code <input name="totp" inputmode="numeric" autocomplete="one-time-code"></label>
  <button type="submit">Sign in</button>
</form>`))

// registerOIDCRoutes mounts the standard OIDC wire routes on the host's own
// mux. The framework-neutral dispatch contract now owns all OAuth parameter
// parsing and response mapping. This example only translates net/http values
// and renders the human interaction SESAME deliberately does not ship.
func registerOIDCRoutes(mux *http.ServeMux, client *sesame.Client, tenantID string) {
	endpoints := &sesame.DiscoveryEndpoints{
		AuthorizationEndpoint: "/authorize",
		TokenEndpoint:         "/token",
		JWKSURI:               "/.well-known/jwks.json",
		IntrospectionEndpoint: "/introspect",
		RevocationEndpoint:    "/revoke",
		EndSessionEndpoint:    "/logout",
	}

	mux.HandleFunc("GET /.well-known/openid-configuration",
		standardEndpoint(client, "oidc.discovery", endpoints))
	mux.HandleFunc("GET /.well-known/jwks.json",
		standardEndpoint(client, "oidc.jwks", nil))
	mux.HandleFunc("POST /token",
		standardEndpoint(client, "oidc.token", nil))
	mux.HandleFunc("POST /introspect",
		standardEndpoint(client, "oidc.introspection", nil))
	mux.HandleFunc("POST /revoke",
		standardEndpoint(client, "oidc.revocation", nil))

	mux.HandleFunc("GET /logout", func(writer http.ResponseWriter, request *http.Request) {
		response, ok := dispatchStandard(writer, request, client, "oidc.logout", nil)
		if !ok {
			return
		}
		if response.Status < http.StatusBadRequest {
			clearCookies(writer)
		}
		serveStandardResponse(writer, response)
	})

	mux.HandleFunc("GET /authorize", func(writer http.ResponseWriter, request *http.Request) {
		response, ok := dispatchStandard(writer, request, client, "oidc.authorization", nil)
		if !ok {
			return
		}
		serveAuthorizationResponse(writer, response)
	})

	mux.HandleFunc("POST /login", func(writer http.ResponseWriter, request *http.Request) {
		interactionID, interactionSecret, ok := readPair(request, interactionCookie)
		if !ok {
			writeJSON(writer, http.StatusBadRequest, map[string]any{"error": "no interaction in progress"})
			return
		}
		if err := request.ParseForm(); err != nil {
			writeJSON(writer, http.StatusBadRequest, map[string]any{"error": "malformed form"})
			return
		}

		sessionID, sessionSecret, err := signIn(request, client, tenantID,
			request.PostFormValue("email"), request.PostFormValue("password"), request.PostFormValue("totp"))
		if err != nil {
			// One message for every failure: which of email, password, and
			// code was wrong is not the browser's business.
			renderLogin(writer, "", "Those credentials did not work.")
			return
		}

		response, err := client.InteractionComplete(request.Context(),
			interactionID, interactionSecret, sessionID, sessionSecret)
		if err != nil {
			// consent_required is not a failure. The engine is telling the
			// host to ask the user, and the interaction is still live.
			var protocolError *sesame.ProtocolError
			if errors.As(err, &protocolError) && protocolError.Code == "consent_required" {
				// The session has to survive the consent round trip; a real
				// host would keep it in its own session store rather than a
				// cookie, and would never put the secret in a URL.
				http.SetCookie(writer, sessionCookie(sessionID, sessionSecret))
				renderConsent(writer, request, client, interactionID)
				return
			}
			writeJSON(writer, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		redirectWithCode(writer, request, response)
	})

	mux.HandleFunc("POST /consent", func(writer http.ResponseWriter, request *http.Request) {
		interactionID, interactionSecret, ok := readPair(request, interactionCookie)
		if !ok {
			writeJSON(writer, http.StatusBadRequest, map[string]any{"error": "no interaction in progress"})
			return
		}
		sessionID, sessionSecret, ok := readPair(request, sessionCookieName)
		if !ok {
			writeJSON(writer, http.StatusBadRequest, map[string]any{"error": "no session in progress"})
			return
		}
		if err := request.ParseForm(); err != nil {
			writeJSON(writer, http.StatusBadRequest, map[string]any{"error": "malformed form"})
			return
		}
		if request.PostFormValue("decision") != "allow" {
			// A denial ends the interaction here. It is deliberately not
			// redirected back to the client with an error: this host has no
			// reason to hand a declining user onward.
			clearCookies(writer)
			writeJSON(writer, http.StatusOK, map[string]any{"error": "access_denied"})
			return
		}

		interaction, err := client.InteractionGet(request.Context(), interactionID)
		if err != nil {
			writeJSON(writer, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		// The scopes consented to are the ones the engine recorded on the
		// interaction, not any the browser posted back.
		if _, err := client.ConsentGrant(request.Context(), sessionID, sessionSecret,
			interaction.ClientID, interaction.Scopes); err != nil {
			writeJSON(writer, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}

		response, err := client.InteractionComplete(request.Context(),
			interactionID, interactionSecret, sessionID, sessionSecret)
		if err != nil {
			writeJSON(writer, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		redirectWithCode(writer, request, response)
	})

}

func serveAuthorizationResponse(writer http.ResponseWriter, response sesame.StandardsResponse) {
	if !applyStandardResponseHeaders(writer, response) {
		return
	}
	if response.Action == nil {
		writeStandardResponse(writer, response)
		return
	}
	http.SetCookie(writer, &http.Cookie{
		Name:     interactionCookie,
		Value:    response.Action.InteractionID + ":" + response.Action.InteractionSecret,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((15 * time.Minute).Seconds()),
	})
	renderLogin(writer, response.Action.ClientName, "")
}

// redirectWithCode sends the browser back to the client. The target is the
// URI the engine validated at /authorize, never anything read off the current
// request.
func redirectWithCode(
	writer http.ResponseWriter,
	request *http.Request,
	response sesame.AuthorizationResponse,
) {
	// The cookies have done their job; leaving them would let a later request
	// resume an interaction the user has finished with.
	clearCookies(writer)

	target, err := url.Parse(response.RedirectURI)
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]any{"error": "server_error"})
		return
	}
	parameters := target.Query()
	parameters.Set("code", response.Code)
	if response.State != "" {
		parameters.Set("state", response.State)
	}
	target.RawQuery = parameters.Encode()
	http.Redirect(writer, request, target.String(), http.StatusSeeOther)
}

func clearCookies(writer http.ResponseWriter) {
	for _, name := range []string{interactionCookie, sessionCookieName} {
		http.SetCookie(writer, &http.Cookie{Name: name, Path: "/", MaxAge: -1})
	}
}

// readPair reads one "id:secret" cookie.
func readPair(request *http.Request, name string) (string, string, bool) {
	cookie, err := request.Cookie(name)
	if err != nil {
		return "", "", false
	}
	id, secret, found := strings.Cut(cookie.Value, ":")
	return id, secret, found
}

// sessionCookie carries the authenticated session across the consent round
// trip. It is bearer-equivalent for that window, so it is HttpOnly, Secure,
// and short-lived.
func sessionCookie(sessionID, sessionSecret string) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID + ":" + sessionSecret,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((15 * time.Minute).Seconds()),
	}
}

func renderConsent(
	writer http.ResponseWriter,
	request *http.Request,
	client *sesame.Client,
	interactionID string,
) {
	interaction, err := client.InteractionGet(request.Context(), interactionID)
	if err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	registered, err := client.ClientGet(request.Context(), interaction.ClientID)
	if err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := consentPage.Execute(writer, struct {
		ClientName string
		Scopes     []string
	}{ClientName: registered.Name, Scopes: interaction.Scopes}); err != nil {
		log.Printf("render consent: %v", err)
	}
}

// signIn runs the ordinary authentication flow. The host chooses how a user
// proves identity; the engine decides whether the proof holds.
func signIn(
	request *http.Request,
	client *sesame.Client,
	tenantID, email, password, totp string,
) (string, string, error) {
	identifier := sesame.PrincipalIdentifier{Namespace: "email", Value: email}
	begun, err := client.AuthenticationBegin(request.Context(), tenantID, identifier)
	if err != nil {
		return "", "", err
	}
	if _, err := client.AuthenticationVerifyPassword(request.Context(), begun.TransactionID, password); err != nil {
		return "", "", err
	}
	if totp != "" {
		if _, err := client.AuthenticationVerifyTOTP(request.Context(), begun.TransactionID, totp); err != nil {
			return "", "", err
		}
	}
	session, err := client.AuthenticationComplete(request.Context(), begun.TransactionID, 0)
	if err != nil {
		return "", "", err
	}
	return session.SessionID, session.Secret, nil
}

func renderLogin(writer http.ResponseWriter, clientName, message string) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := loginPage.Execute(writer, struct {
		ClientName string
		Error      string
	}{ClientName: clientName, Error: message}); err != nil {
		log.Printf("render login: %v", err)
	}
}
