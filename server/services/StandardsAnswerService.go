import (
	"bytes"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Service
// @NeedsAll
type StandardsAnswerService struct {
	standardsRefusalService  *StandardsRefusalService
	interactionCookieService *InteractionCookieService
}

func (service *StandardsAnswerService) Answer(response sesame.StandardsResponse, failure error) (*http.Response, error) {
	return service.answered(service.rendered(service.ordinary(response)), failure)
}

func (service *StandardsAnswerService) Authorize(response sesame.StandardsResponse, failure error) (*http.Response, error) {
	plain := service.rendered(service.ordinary(response))
	interactive := service.interaction(response)
	return service.answered(service.chosen(response.Action == nil, plain, interactive), failure)
}

func (service *StandardsAnswerService) answered(answer *http.Response, failure error) (*http.Response, error) {
	if failure != nil {
		return nil, failure
	}
	return answer, nil
}

func (service *StandardsAnswerService) chosen(plainWanted bool, plain *http.Response, interactive *http.Response) *http.Response {
	if plainWanted {
		return plain
	}
	return interactive
}

func (service *StandardsAnswerService) ordinary(response sesame.StandardsResponse) sesame.StandardsResponse {
	if !service.plain(response) {
		return service.unavailable()
	}
	return response
}

func (service *StandardsAnswerService) plain(response sesame.StandardsResponse) bool {
	return !slices.Contains([]bool{response.Action == nil, service.valid(response)}, false)
}

func (service *StandardsAnswerService) interaction(response sesame.StandardsResponse) *http.Response {
	if !service.interactive(response) {
		return service.rendered(service.unavailable())
	}
	answer := service.rendered(service.interactionCookieService.Public(response))
	answer.Header.Add(service.cookieHeader(), service.interactionCookieService.Cookie(*response.Action).String())
	return answer
}

func (service *StandardsAnswerService) cookieHeader() string {
	return "Set-Cookie"
}

func (service *StandardsAnswerService) interactive(response sesame.StandardsResponse) bool {
	return !slices.Contains([]bool{response.Action != nil, service.valid(response)}, false)
}

func (service *StandardsAnswerService) valid(response sesame.StandardsResponse) bool {
	checks := []bool{
		response.ContractVersion == service.contractVersion(),
		response.Status >= http.StatusOK,
		response.Status <= service.highestStatus(),
		service.actionAllowed(response),
		service.headersAllowed(response.Headers),
	}
	return !slices.Contains(checks, false)
}

func (service *StandardsAnswerService) contractVersion() string {
	return "1"
}

func (service *StandardsAnswerService) highestStatus() int {
	return 599
}

func (service *StandardsAnswerService) actionAllowed(response sesame.StandardsResponse) bool {
	if response.Action == nil {
		return true
	}
	return service.interactionShaped(response)
}

func (service *StandardsAnswerService) interactionShaped(response sesame.StandardsResponse) bool {
	checks := []bool{
		response.Status == http.StatusOK,
		len(response.Body) == 0,
		response.Action.Kind == service.interactionKind(),
	}
	return !slices.Contains(checks, false)
}

func (service *StandardsAnswerService) interactionKind() string {
	return "interaction"
}

func (service *StandardsAnswerService) headersAllowed(headers map[string]string) bool {
	checks := []bool{}
	names := service.allowedHeaders()
	for name, value := range headers {
		checks = append(checks, slices.Contains(names, strings.ToLower(name)), !strings.ContainsAny(value, service.lineBreaks()))
	}
	return !slices.Contains(checks, false)
}

func (service *StandardsAnswerService) allowedHeaders() []string {
	return []string{
		"allow", "cache-control", "content-type", "location", "pragma",
		"www-authenticate", "x-content-type-options",
	}
}

func (service *StandardsAnswerService) lineBreaks() string {
	return "\r\n"
}

func (service *StandardsAnswerService) rendered(response sesame.StandardsResponse) *http.Response {
	headers := service.headers(response.Headers)
	service.typeEmptyBody(headers, response.Body)
	return &http.Response{
		StatusCode:    response.Status,
		Header:        headers,
		Body:          io.NopCloser(bytes.NewReader(response.Body)),
		ContentLength: int64(len(response.Body)),
	}
}

func (service *StandardsAnswerService) headers(values map[string]string) http.Header {
	headers := http.Header{}
	for name, value := range values {
		headers.Set(name, value)
	}
	return headers
}

func (service *StandardsAnswerService) typeEmptyBody(headers http.Header, body []byte) {
	missing := []bool{len(body) == 0, headers.Get(service.contentTypeHeader()) == ""}
	if !slices.Contains(missing, false) {
		headers.Set(service.contentTypeHeader(), service.emptyBodyType())
	}
}

func (service *StandardsAnswerService) contentTypeHeader() string {
	return "Content-Type"
}

func (service *StandardsAnswerService) emptyBodyType() string {
	return "text/plain; charset=utf-8"
}

func (service *StandardsAnswerService) unavailable() sesame.StandardsResponse {
	return service.standardsRefusalService.Refusal(http.StatusServiceUnavailable, service.serverError())
}

func (service *StandardsAnswerService) serverError() string {
	return "server_error"
}
