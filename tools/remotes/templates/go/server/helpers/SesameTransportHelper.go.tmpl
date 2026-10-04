import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"time"
)

// @Helper
type SesameTransportHelper struct{}

func (helper *SesameTransportHelper) Exchange(request *BehaviorHttpRequest, execution *BehaviorExecution) (BehaviorValue, error) {
	deadline, cancel := context.WithDeadline(context.Background(), time.UnixMilli(execution.Deadline))
	defer cancel()
	origin, failure := helper.origin()
	payload, failure := helper.payload(request, failure)
	outgoing, failure := helper.outgoing(request, helper.address(origin, request), payload, failure)
	response, failure := helper.send(deadline, outgoing, request.Headers, failure)
	content, failure := helper.read(response, request.MaxResponseBytes, failure)
	failure = helper.bounded(content, request.MaxResponseBytes, failure)
	return helper.answer(response, content, failure)
}

func (helper *SesameTransportHelper) origin() (url.URL, error) {
	var snapshot struct {
		Yon struct {
			Sesame struct {
				Origin string `json:"origin"`
			} `json:"sesame"`
		} `json:"yon"`
	}
	failure := json.Unmarshal([]byte(os.Getenv(helper.snapshotVariable())), &snapshot)
	parsed, parseFailure := url.Parse(snapshot.Yon.Sesame.Origin)
	return helper.trusted(parsed, errors.Join(failure, parseFailure))
}

func (helper *SesameTransportHelper) trusted(origin *url.URL, failure error) (url.URL, error) {
	if failure != nil || !helper.usable(origin) {
		return url.URL{}, errors.New(helper.originRule())
	}
	return *origin, nil
}

func (helper *SesameTransportHelper) usable(origin *url.URL) bool {
	checks := []bool{
		helper.allowedScheme(origin),
		origin.Host != "",
		origin.User == nil,
		origin.Opaque == "",
		slices.Contains(helper.rootPaths(), origin.Path),
		origin.RawQuery == "",
		!origin.ForceQuery,
		origin.Fragment == "",
	}
	return !slices.Contains(checks, false)
}

func (helper *SesameTransportHelper) allowedScheme(origin *url.URL) bool {
	secure := origin.Scheme == helper.secureScheme()
	local := origin.Scheme == helper.plainScheme() && slices.Contains(helper.loopbackHosts(), origin.Hostname())
	return secure || local
}

func (helper *SesameTransportHelper) address(origin url.URL, request *BehaviorHttpRequest) string {
	origin.Path = request.Path
	origin.RawQuery = helper.query(request.Query).Encode()
	return origin.String()
}

func (helper *SesameTransportHelper) query(values map[string]any) url.Values {
	query := url.Values{}
	for name, value := range values {
		query.Set(name, fmt.Sprint(value))
	}
	return query
}

func (helper *SesameTransportHelper) payload(request *BehaviorHttpRequest, failure error) ([]byte, error) {
	if failure != nil || !request.HasBody {
		return nil, failure
	}
	return json.Marshal(request.Body)
}

func (helper *SesameTransportHelper) outgoing(request *BehaviorHttpRequest, address string, payload []byte, failure error) (*http.Request, error) {
	if failure != nil {
		return nil, failure
	}
	return http.NewRequest(request.Method, address, bytes.NewReader(payload))
}

func (helper *SesameTransportHelper) send(deadline context.Context, outgoing *http.Request, headers map[string]any, failure error) (*http.Response, error) {
	if failure != nil {
		return nil, failure
	}
	helper.copyHeaders(outgoing.Header, headers)
	return helper.client().Do(outgoing.WithContext(deadline))
}

func (helper *SesameTransportHelper) copyHeaders(target http.Header, headers map[string]any) {
	target.Set(helper.contentTypeHeader(), helper.jsonType())
	target.Set(helper.acceptHeader(), helper.jsonType())
	for name, value := range headers {
		target.Set(name, fmt.Sprint(value))
	}
}

func (helper *SesameTransportHelper) client() *http.Client {
	return &http.Client{CheckRedirect: helper.refuseRedirect}
}

func (helper *SesameTransportHelper) refuseRedirect(request *http.Request, previous []*http.Request) error {
	return errors.New(helper.redirectRule())
}

func (helper *SesameTransportHelper) read(response *http.Response, limit int, failure error) ([]byte, error) {
	if failure != nil {
		return nil, failure
	}
	defer response.Body.Close()
	return io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
}

func (helper *SesameTransportHelper) bounded(content []byte, limit int, failure error) error {
	if failure == nil && len(content) > limit {
		return errors.New(helper.sizeRule())
	}
	return failure
}

func (helper *SesameTransportHelper) answer(response *http.Response, content []byte, failure error) (BehaviorValue, error) {
	if failure != nil {
		return nil, failure
	}
	return map[string]any{"status": response.StatusCode, "body": helper.jsonOrNothing(content)}, nil
}

func (helper *SesameTransportHelper) jsonOrNothing(content []byte) BehaviorValue {
	var value BehaviorValue
	json.Unmarshal(content, &value)
	return value
}

func (helper *SesameTransportHelper) snapshotVariable() string {
	return "YON_APPLICATION_JSON"
}

func (helper *SesameTransportHelper) rootPaths() []string {
	return []string{"", "/"}
}

func (helper *SesameTransportHelper) secureScheme() string {
	return "https"
}

func (helper *SesameTransportHelper) plainScheme() string {
	return "http"
}

func (helper *SesameTransportHelper) loopbackHosts() []string {
	return []string{"localhost", "127.0.0.1", "::1"}
}

func (helper *SesameTransportHelper) contentTypeHeader() string {
	return "Content-Type"
}

func (helper *SesameTransportHelper) acceptHeader() string {
	return "Accept"
}

func (helper *SesameTransportHelper) jsonType() string {
	return "application/json"
}

func (helper *SesameTransportHelper) originRule() string {
	return "sesame.origin must be an https origin without a path, or http on a loopback address"
}

func (helper *SesameTransportHelper) redirectRule() string {
	return "SESAME answered with a redirect, which this transport never follows"
}

func (helper *SesameTransportHelper) sizeRule() string {
	return "SESAME's answer is larger than the response limit"
}
