package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInteractionCookieCarriesTheSecurePrefix(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	serveAuthorizationResponse(recorder, validInteractionResponse())

	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("interaction cookies = %#v", cookies)
	}
	if !strings.HasPrefix(cookies[0].Name, "__Secure-") {
		t.Fatalf("interaction cookie name = %q, want the __Secure- prefix", cookies[0].Name)
	}
	if !cookies[0].Secure || cookies[0].Domain != "" {
		t.Fatalf("a __Secure- cookie must be Secure and host-only: %#v", cookies[0])
	}
}

func TestClearingCookiesKeepsTheSecureAttribute(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	clearCookies(recorder)

	cookies := recorder.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("cleared cookies = %#v", cookies)
	}
	for _, cookie := range cookies {
		if !cookie.Secure || cookie.MaxAge >= 0 {
			t.Fatalf("a browser ignores a clearing cookie without Secure for a __Secure- name: %#v", cookie)
		}
	}
}
