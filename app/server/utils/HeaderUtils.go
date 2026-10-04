import (
	"net/http"
	"strings"
)

type HeaderUtils struct{}

func (HeaderUtils) Authorization() string {
	return "Authorization"
}

func (HeaderUtils) Single(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	return strings.Join(values, ""), len(values) <= 1
}

func (HeaderUtils) BearerToken(header http.Header) string {
	scheme, token, _ := strings.Cut(header.Get(HeaderUtils{}.Authorization()), " ")
	return HeaderUtils{}.bearerOnly(scheme, strings.TrimSpace(token))
}

func (HeaderUtils) bearerOnly(scheme string, token string) string {
	if !strings.EqualFold(scheme, HeaderUtils{}.bearerScheme()) {
		return ""
	}
	return token
}

func (HeaderUtils) bearerScheme() string {
	return "Bearer"
}
