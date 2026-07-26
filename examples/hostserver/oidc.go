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
// mux. The paths are the host's to choose; these are the conventional ones.
func registerOIDCRoutes(mux *http.ServeMux, client *sesame.Client, tenantID string) {
	// Discovery names this host's own routes. The engine composes them under
	// the configured issuer and refuses any that would leave that origin, so
	// a typo here fails loudly instead of pointing relying parties elsewhere.
	mux.HandleFunc("GET /.well-known/openid-configuration", func(writer http.ResponseWriter, request *http.Request) {
		metadata, err := client.Discovery(request.Context(), sesame.DiscoveryEndpoints{
			AuthorizationEndpoint: "/authorize",
			TokenEndpoint:         "/token",
			JWKSURI:               "/.well-known/jwks.json",
			IntrospectionEndpoint: "/introspect",
			RevocationEndpoint:    "/revoke",
			EndSessionEndpoint:    "/logout",
		})
		if err != nil {
			log.Printf("discovery: %v", err)
			writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"error": "server_error"})
			return
		}
		writeJSON(writer, http.StatusOK, metadata)
	})

	// Both back-channel endpoints authenticate the calling client the same
	// way the token endpoint does.
	mux.HandleFunc("POST /introspect", func(writer http.ResponseWriter, request *http.Request) {
		clientID, clientSecret, token, ok := backChannelRequest(request)
		if !ok {
			writeJSON(writer, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
			return
		}
		result, err := client.Introspect(request.Context(), clientID, clientSecret, token)
		if err != nil {
			// A caller that cannot authenticate is told so; it is not told
			// anything about the token.
			writeJSON(writer, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writeJSON(writer, http.StatusOK, result)
	})

	mux.HandleFunc("POST /revoke", func(writer http.ResponseWriter, request *http.Request) {
		clientID, clientSecret, token, ok := backChannelRequest(request)
		if !ok {
			writeJSON(writer, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
			return
		}
		if err := client.Revoke(request.Context(), clientID, clientSecret, token); err != nil {
			writeJSON(writer, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
			return
		}
		// RFC 7009: success whether or not there was anything to revoke.
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusOK)
	})

	// RP-initiated logout. The hint identifies the session; the engine
	// decides whether the return URI is one this client registered.
	mux.HandleFunc("GET /logout", func(writer http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		result, err := client.Logout(request.Context(),
			query.Get("id_token_hint"),
			query.Get("post_logout_redirect_uri"),
			query.Get("state"))
		if err != nil {
			// Rendered rather than redirected: the request has not proven a
			// return URI worth trusting.
			writeJSON(writer, http.StatusBadRequest, map[string]any{
				"error":             "invalid_request",
				"error_description": err.Error(),
			})
			return
		}
		clearCookies(writer)
		if result.RedirectURI == "" {
			writeJSON(writer, http.StatusOK, map[string]any{"signed_out": true})
			return
		}
		target, err := url.Parse(result.RedirectURI)
		if err != nil {
			writeJSON(writer, http.StatusInternalServerError, map[string]any{"error": "server_error"})
			return
		}
		if result.State != "" {
			parameters := target.Query()
			parameters.Set("state", result.State)
			target.RawQuery = parameters.Encode()
		}
		http.Redirect(writer, request, target.String(), http.StatusSeeOther)
	})

	mux.HandleFunc("GET /.well-known/jwks.json", func(writer http.ResponseWriter, request *http.Request) {
		keys, err := client.SigningKeys(request.Context())
		if err != nil {
			log.Printf("jwks: %v", err)
			writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"error": "server_error"})
			return
		}
		writeJSON(writer, http.StatusOK, keys)
	})

	mux.HandleFunc("GET /authorize", func(writer http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		// Nothing is shown to the user until the engine has accepted the
		// request. An invalid redirect URI in particular must never reach a
		// page that could then redirect to it.
		started, err := client.Authorize(request.Context(), sesame.AuthorizationRequest{
			ClientID:            query.Get("client_id"),
			RedirectURI:         query.Get("redirect_uri"),
			ResponseType:        query.Get("response_type"),
			Scopes:              strings.Fields(query.Get("scope")),
			State:               query.Get("state"),
			Nonce:               query.Get("nonce"),
			CodeChallenge:       query.Get("code_challenge"),
			CodeChallengeMethod: query.Get("code_challenge_method"),
		})
		if err != nil {
			// The error is rendered here rather than redirected: the request
			// has not yet proven a redirect URI worth trusting.
			writeJSON(writer, http.StatusBadRequest, map[string]any{
				"error":             "invalid_request",
				"error_description": err.Error(),
			})
			return
		}

		http.SetCookie(writer, &http.Cookie{
			Name:     interactionCookie,
			Value:    started.InteractionID + ":" + started.Secret,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int((15 * time.Minute).Seconds()),
		})
		renderLogin(writer, started.ClientName, "")
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

	mux.HandleFunc("POST /token", func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			writeJSON(writer, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
			return
		}
		// Client credentials may arrive in the body or as HTTP Basic. Both
		// are standard; the engine sees the same two values either way.
		clientID := request.PostFormValue("client_id")
		clientSecret := request.PostFormValue("client_secret")
		if basicID, basicSecret, ok := request.BasicAuth(); ok {
			clientID, clientSecret = basicID, basicSecret
		}

		// Both grants come through this one endpoint, exactly as the specs
		// define. The engine decides which fields matter.
		tokens, err := client.TokenExchange(request.Context(), sesame.TokenRequest{
			GrantType:    request.PostFormValue("grant_type"),
			Code:         request.PostFormValue("code"),
			RedirectURI:  request.PostFormValue("redirect_uri"),
			ClientID:     clientID,
			ClientSecret: clientSecret,
			CodeVerifier: request.PostFormValue("code_verifier"),
			RefreshToken: request.PostFormValue("refresh_token"),
			Scope:        request.PostFormValue("scope"),
		})
		if err != nil {
			var protocolError *sesame.ProtocolError
			code := "invalid_request"
			if errors.As(err, &protocolError) && protocolError.Code == "invalid_grant" {
				code = "invalid_grant"
			}
			// Token endpoint errors are 400 with an OAuth error code and no
			// detail: the engine already refused to say which check failed.
			writer.Header().Set("Cache-Control", "no-store")
			writeJSON(writer, http.StatusBadRequest, map[string]any{"error": code})
			return
		}
		// A refresh response carries a new refresh token that replaces the
		// one the client sent. A client that keeps using the old one will
		// have its whole family revoked.
		writer.Header().Set("Cache-Control", "no-store")
		writeJSON(writer, http.StatusOK, tokens)
	})
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

// backChannelRequest reads the client credentials and token from an
// introspection or revocation request. Credentials may arrive as HTTP Basic
// or in the body; both are standard.
func backChannelRequest(request *http.Request) (clientID, clientSecret, token string, ok bool) {
	if err := request.ParseForm(); err != nil {
		return "", "", "", false
	}
	clientID = request.PostFormValue("client_id")
	clientSecret = request.PostFormValue("client_secret")
	if basicID, basicSecret, present := request.BasicAuth(); present {
		clientID, clientSecret = basicID, basicSecret
	}
	token = request.PostFormValue("token")
	return clientID, clientSecret, token, clientID != ""
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
