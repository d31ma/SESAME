package main

import (
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/d31ma/sesame/clients/go/sesame"
)

const maxStandardsBodyBytes = 128 * 1024

func standardEndpoint(
	client *sesame.Client,
	endpoint string,
	endpoints *sesame.DiscoveryEndpoints,
) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		response, ok := dispatchStandard(writer, request, client, endpoint, endpoints)
		if ok {
			serveStandardResponse(writer, response)
		}
	}
}

// dispatchStandard is the entire net/http-to-contract translation. A
// SvelteKit, Next, Nuxt, or Solid adapter performs the equivalent three
// mechanical steps with its framework's request type: preserve duplicate
// query/form values, copy the two allowlisted headers, call the SDK.
func dispatchStandard(
	writer http.ResponseWriter,
	request *http.Request,
	client *sesame.Client,
	endpoint string,
	endpoints *sesame.DiscoveryEndpoints,
) (sesame.StandardsResponse, bool) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxStandardsBodyBytes)
	if request.Method == http.MethodPost {
		if err := request.ParseForm(); err != nil {
			writeStandardError(writer, http.StatusBadRequest, "invalid_request")
			return sesame.StandardsResponse{}, false
		}
	}

	authorization, authorizationOK := singleSecurityHeader(request.Header, "Authorization")
	dpop, dpopOK := singleSecurityHeader(request.Header, "DPoP")
	if !authorizationOK || !dpopOK {
		writeStandardError(writer, http.StatusBadRequest, "invalid_request")
		return sesame.StandardsResponse{}, false
	}

	translated := sesame.StandardsRequest{
		ContractVersion: "1",
		Endpoint:        endpoint,
		Method:          request.Method,
		Query:           cloneValues(request.URL.Query()),
		Authorization:   authorization,
		DPoP:            dpop,
		Endpoints:       endpoints,
	}
	if request.Method == http.MethodPost {
		translated.Form = cloneValues(request.PostForm)
	}
	if translated.DPoP != "" {
		translated.HTTPURI = publicRequestURI(request)
	}

	response, err := client.StandardsDispatch(request.Context(), translated)
	if err != nil {
		log.Printf("standards dispatch %s: %v", endpoint, err)
		writeStandardError(writer, http.StatusServiceUnavailable, "server_error")
		return sesame.StandardsResponse{}, false
	}
	return response, true
}

func singleSecurityHeader(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	switch len(values) {
	case 0:
		return "", true
	case 1:
		return values[0], true
	default:
		return "", false
	}
}

func cloneValues(values url.Values) map[string][]string {
	cloned := make(map[string][]string, len(values))
	for key, entries := range values {
		cloned[key] = append([]string(nil), entries...)
	}
	return cloned
}

func publicRequestURI(request *http.Request) string {
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + request.Host + request.URL.EscapedPath()
}

// serveStandardResponse validates and emits an ordinary contract response.
func serveStandardResponse(writer http.ResponseWriter, response sesame.StandardsResponse) {
	if !applyStandardResponseHeaders(writer, response) {
		return
	}
	writeStandardResponse(writer, response)
}

// applyStandardResponseHeaders validates the complete response before applying
// any header. Callers that render an action can then preserve contract headers
// without emitting the contract status or body first.
func applyStandardResponseHeaders(writer http.ResponseWriter, response sesame.StandardsResponse) bool {
	if !validateStandardResponse(response) {
		writeStandardError(writer, http.StatusServiceUnavailable, "server_error")
		return false
	}
	for name, value := range response.Headers {
		writer.Header().Set(name, value)
	}
	return true
}

func validateStandardResponse(response sesame.StandardsResponse) bool {
	if response.ContractVersion != "1" ||
		response.Status < http.StatusOK ||
		response.Status > 599 ||
		(response.Action != nil && response.Status != http.StatusOK) ||
		(response.Action != nil && len(response.Body) != 0) ||
		(response.Action != nil && response.Action.Kind != "interaction") {
		return false
	}
	for name, value := range response.Headers {
		if !standardResponseHeader(name) || strings.ContainsAny(value, "\r\n") {
			return false
		}
	}
	return true
}

func writeStandardError(writer http.ResponseWriter, status int, code string) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	writeJSON(writer, status, map[string]any{"error": code})
}

func writeStandardResponse(writer http.ResponseWriter, response sesame.StandardsResponse) {
	writer.WriteHeader(response.Status)
	if len(response.Body) != 0 {
		if _, err := writer.Write(response.Body); err != nil {
			log.Printf("write standards response: %v", err)
		}
	}
}

func standardResponseHeader(name string) bool {
	switch strings.ToLower(name) {
	case "allow", "cache-control", "content-type", "location", "pragma",
		"www-authenticate", "x-content-type-options":
		return true
	default:
		return false
	}
}
