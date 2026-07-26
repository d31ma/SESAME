package main

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/d31ma/sesame/clients/go/sesame"
)

func TestHostTranslationPreservesDuplicateValues(t *testing.T) {
	t.Parallel()

	source := url.Values{
		"client_id": {"first", "second"},
		"scope":     {"openid profile"},
	}
	cloned := cloneValues(source)
	source["client_id"][0] = "changed"
	if len(cloned["client_id"]) != 2 ||
		cloned["client_id"][0] != "first" ||
		cloned["client_id"][1] != "second" {
		t.Fatalf("cloneValues() = %#v", cloned)
	}
}

func TestPublicRequestURIReportsTheRouteWithoutQuery(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodPost,
		"https://id.example/token?attacker=ignored", http.NoBody)
	request.TLS = &tls.ConnectionState{}
	if got := publicRequestURI(request); got != "https://id.example/token" {
		t.Fatalf("publicRequestURI() = %q", got)
	}
}

func TestHostRejectsDuplicateSecurityHeadersBeforeDispatch(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"Authorization", "DPoP"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequest(http.MethodGet, "https://id.example/authorize", http.NoBody)
			request.Header.Add(name, "first")
			request.Header.Add(name, "second")
			recorder := httptest.NewRecorder()

			if _, ok := dispatchStandard(
				recorder,
				request,
				nil,
				"oidc.authorization",
				nil,
			); ok {
				t.Fatalf("duplicate %s header reached SESAME dispatch", name)
			}
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
			}
			if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", got)
			}
			if got := recorder.Header().Get("Pragma"); got != "no-cache" {
				t.Fatalf("Pragma = %q, want no-cache", got)
			}
			if recorder.Body.String() != "{\"error\":\"invalid_request\"}\n" {
				t.Fatalf("body = %q", recorder.Body.String())
			}
		})
	}
}

func TestHostRejectsHeadersOutsideTheContractAllowlist(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	serveStandardResponse(recorder, sesame.StandardsResponse{
		ContractVersion: "1",
		Status:          http.StatusOK,
		Headers:         map[string]string{"set-cookie": "secret=leak"},
	})
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if cookie := recorder.Header().Get("Set-Cookie"); cookie != "" {
		t.Fatalf("unapproved response header escaped: %q", cookie)
	}
}

func TestAuthorizationActionRejectsInvalidContractResponses(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*sesame.StandardsResponse){
		"unsupported contract version": func(response *sesame.StandardsResponse) {
			response.ContractVersion = "2"
		},
		"status below contract range": func(response *sesame.StandardsResponse) {
			response.Status = 199
		},
		"status above contract range": func(response *sesame.StandardsResponse) {
			response.Status = 600
		},
		"error status with action": func(response *sesame.StandardsResponse) {
			response.Status = http.StatusBadRequest
		},
		"header outside allowlist": func(response *sesame.StandardsResponse) {
			response.Headers["set-cookie"] = "stolen=secret"
		},
		"header value with newline": func(response *sesame.StandardsResponse) {
			response.Headers["cache-control"] = "no-store\r\nSet-Cookie: stolen=secret"
		},
		"body alongside action": func(response *sesame.StandardsResponse) {
			response.Body = json.RawMessage(`{"interaction_secret":"leaked"}`)
		},
		"unknown action kind": func(response *sesame.StandardsResponse) {
			response.Action.Kind = "redirect"
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			response := validInteractionResponse()
			mutate(&response)
			recorder := httptest.NewRecorder()

			serveAuthorizationResponse(recorder, response)

			if recorder.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
			}
			if cookies := recorder.Result().Cookies(); len(cookies) != 0 {
				t.Fatalf("invalid action set cookies: %#v", cookies)
			}
			if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("failure Cache-Control = %q, want no-store", got)
			}
			if got := recorder.Header().Get("Pragma"); got != "no-cache" {
				t.Fatalf("failure Pragma = %q, want no-cache", got)
			}
			if strings.Contains(recorder.Body.String(), response.Action.InteractionSecret) {
				t.Fatal("interaction secret reached the failure response")
			}
		})
	}
}

func TestAuthorizationActionAppliesContractHeadersBeforeRendering(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	serveAuthorizationResponse(recorder, validInteractionResponse())

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := recorder.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache", got)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want HTML", got)
	}
	if strings.Contains(recorder.Body.String(), "interaction-secret") {
		t.Fatal("interaction secret reached rendered HTML")
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != interactionCookie {
		t.Fatalf("interaction cookies = %#v", cookies)
	}
	if !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatalf("interaction cookie is not secure: %#v", cookies[0])
	}
}

func validInteractionResponse() sesame.StandardsResponse {
	return sesame.StandardsResponse{
		ContractVersion: "1",
		Status:          http.StatusOK,
		Headers: map[string]string{
			"cache-control": "no-store",
			"pragma":        "no-cache",
		},
		Action: &sesame.StandardsInteraction{
			Kind:              "interaction",
			InteractionID:     "interaction-id",
			InteractionSecret: "interaction-secret",
			ClientID:          "client-id",
			ClientName:        "Example Client",
			Scopes:            []string{"openid"},
			ExpiresAt:         "2026-07-26T17:00:00Z",
		},
	}
}
