import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/d31ma/sesame/app/server/packages/sesame"
)

// @Service
// @NeedsAll
type StandardsDispatchService struct {
	engineService           *EngineService
	standardsRefusalService *StandardsRefusalService
}

func (service *StandardsDispatchService) Dispatch(request *http.Request, endpoint string) (sesame.StandardsResponse, error) {
	translated, usable := service.translate(request, endpoint)
	return service.dispatchWhen(translated, usable)
}

func (service *StandardsDispatchService) translate(request *http.Request, endpoint string) (sesame.StandardsRequest, bool) {
	form, formUsable := service.form(request)
	authorization, authorizationUsable := service.singleHeader(request.Header, service.authorizationHeader())
	proof, proofUsable := service.singleHeader(request.Header, service.proofHeader())
	scheme := service.scheme(request.Header.Get(service.forwardedProtocolHeader()))
	return sesame.StandardsRequest{
		ContractVersion: service.contractVersion(),
		Endpoint:        endpoint,
		Method:          request.Method,
		Query:           service.copied(request.URL.Query()),
		Form:            form,
		Authorization:   authorization,
		DPoP:            proof,
		HTTPURI:         service.publicURI(request, proof, scheme),
		Endpoints:       service.endpoints(endpoint),
	}, !slices.Contains([]bool{formUsable, authorizationUsable, proofUsable}, false)
}

func (service *StandardsDispatchService) authorizationHeader() string {
	return "Authorization"
}

func (service *StandardsDispatchService) dispatchWhen(translated sesame.StandardsRequest, usable bool) (sesame.StandardsResponse, error) {
	if !usable {
		return service.refusal(), nil
	}
	return service.send(translated)
}

func (service *StandardsDispatchService) proofHeader() string {
	return "DPoP"
}

func (service *StandardsDispatchService) send(translated sesame.StandardsRequest) (sesame.StandardsResponse, error) {
	response := sesame.StandardsResponse{}
	failure := service.engineService.Call("standards.dispatch", translated, &response)
	return service.refusedWhenInvalid(response, failure)
}

func (service *StandardsDispatchService) forwardedProtocolHeader() string {
	return "X-Forwarded-Proto"
}

func (service *StandardsDispatchService) refusedWhenInvalid(
	response sesame.StandardsResponse,
	failure error,
) (sesame.StandardsResponse, error) {
	if service.protocolCode(failure) == service.invalidRequest() {
		return service.refusal(), nil
	}
	return response, failure
}

func (service *StandardsDispatchService) contractVersion() string {
	return "1"
}

func (service *StandardsDispatchService) form(request *http.Request) (map[string][]string, bool) {
	if request.Method != http.MethodPost {
		return nil, true
	}
	return service.postedForm(request)
}

func (service *StandardsDispatchService) postedForm(request *http.Request) (map[string][]string, bool) {
	body, failure := io.ReadAll(io.LimitReader(request.Body, service.largestBody()+1))
	request.Body = io.NopCloser(bytes.NewReader(body))
	failure = errors.Join(failure, service.bounded(body), request.ParseForm())
	return service.copied(request.PostForm), failure == nil
}

func (service *StandardsDispatchService) bounded(body []byte) error {
	if int64(len(body)) > service.largestBody() {
		return errors.New("the request body exceeds the standards contract limit")
	}
	return nil
}

func (service *StandardsDispatchService) largestBody() int64 {
	return 128 * 1024
}

func (service *StandardsDispatchService) singleHeader(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	return strings.Join(values, ""), len(values) <= 1
}

func (service *StandardsDispatchService) copied(values url.Values) map[string][]string {
	copied := map[string][]string{}
	for name, entries := range values {
		copied[name] = slices.Clone(entries)
	}
	return copied
}

func (service *StandardsDispatchService) publicURI(request *http.Request, proof string, scheme string) string {
	if proof == "" {
		return ""
	}
	return scheme + "://" + request.Host + request.URL.EscapedPath()
}

func (service *StandardsDispatchService) scheme(forwarded string) string {
	if forwarded == service.secureScheme() {
		return forwarded
	}
	return service.plainScheme()
}

func (service *StandardsDispatchService) secureScheme() string {
	return "https"
}

func (service *StandardsDispatchService) plainScheme() string {
	return "http"
}

func (service *StandardsDispatchService) endpoints(endpoint string) *sesame.DiscoveryEndpoints {
	if endpoint != service.discoveryEndpoint() {
		return nil
	}
	return &sesame.DiscoveryEndpoints{
		AuthorizationEndpoint: "/oidc/authorize",
		TokenEndpoint:         "/oidc/token",
		JWKSURI:               "/oidc/jwks",
		IntrospectionEndpoint: "/oidc/introspect",
		RevocationEndpoint:    "/oidc/revoke",
		EndSessionEndpoint:    "/oidc/logout",
	}
}

func (service *StandardsDispatchService) discoveryEndpoint() string {
	return "oidc.discovery"
}

func (service *StandardsDispatchService) protocolCode(failure error) string {
	protocolError := &sesame.ProtocolError{}
	errors.As(failure, &protocolError)
	return protocolError.Code
}

func (service *StandardsDispatchService) refusal() sesame.StandardsResponse {
	return service.standardsRefusalService.Refusal(http.StatusBadRequest, service.invalidRequest())
}

func (service *StandardsDispatchService) invalidRequest() string {
	return "invalid_request"
}
