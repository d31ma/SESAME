import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/d31ma/sesame/server/packages/host"
)

// @ErrorHandler
type SesameErrorHandler struct{}

// @HandlesError
func (handler *SesameErrorHandler) Answer(failure error) *http.Response {
	code := handler.code(failure)
	status := handler.status(code)
	return handler.response(handler.headers(status, code), status, handler.problem(status, code))
}

func (handler *SesameErrorHandler) code(failure error) string {
	var coded host.CodedError
	if !errors.As(failure, &coded) {
		return ""
	}
	return coded.ErrorCode()
}

func (handler *SesameErrorHandler) status(code string) int {
	status, known := handler.statuses()[code]
	if !known {
		return http.StatusInternalServerError
	}
	return status
}

func (handler *SesameErrorHandler) problem(status int, code string) Problem {
	if status == http.StatusInternalServerError {
		return Problem{Code: "internal_error"}
	}
	return Problem{Code: code}
}

func (handler *SesameErrorHandler) response(headers http.Header, status int, problem Problem) *http.Response {
	body, _ := json.Marshal(problem)
	return &http.Response{
		StatusCode:    status,
		Header:        headers,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func (handler *SesameErrorHandler) headers(status int, code string) http.Header {
	headers := http.Header{}
	headers.Set("Content-Type", "application/json")
	handler.retryLater(headers, status)
	handler.challengeBearer(headers, code)
	return headers
}

func (handler *SesameErrorHandler) retryLater(headers http.Header, status int) {
	if status == http.StatusServiceUnavailable {
		headers.Set("Retry-After", handler.retryAfterSeconds())
	}
}

func (handler *SesameErrorHandler) challengeBearer(headers http.Header, code string) {
	if code == handler.bearerRefusalCode() {
		headers.Set("WWW-Authenticate", handler.bearerChallenge())
	}
}

func (handler *SesameErrorHandler) bearerRefusalCode() string {
	return "provisioning_denied"
}

func (handler *SesameErrorHandler) bearerChallenge() string {
	return "Bearer"
}

func (handler *SesameErrorHandler) retryAfterSeconds() string {
	return "1"
}

func (handler *SesameErrorHandler) statuses() map[string]int {
	statuses := map[string]int{}
	handler.assign(statuses, http.StatusBadRequest, handler.badRequestCodes())
	handler.assign(statuses, http.StatusUnauthorized, handler.unauthorizedCodes())
	handler.assign(statuses, http.StatusForbidden, handler.forbiddenCodes())
	handler.assign(statuses, http.StatusNotFound, handler.notFoundCodes())
	handler.assign(statuses, http.StatusConflict, handler.conflictCodes())
	handler.assign(statuses, http.StatusServiceUnavailable, handler.unavailableCodes())
	return statuses
}

func (handler *SesameErrorHandler) assign(statuses map[string]int, status int, codes []string) {
	for _, code := range codes {
		statuses[code] = status
	}
}

func (handler *SesameErrorHandler) badRequestCodes() []string {
	return []string{
		"invalid_request", "invalid_json", "frame_too_large", "invalid_grant",
		"invalid_redirect_uri", "invalid_logout_hint", "invalid_post_logout_redirect_uri",
		"scope_not_allowed", "totp_invalid_code", "passkey_rejected", "passkey_challenge_expired",
		"assertion_rejected", "saml_assertion_rejected", "provider_document_rejected",
		"federated_login_expired", "dpop_proof_invalid", "dpop_proof_not_bound", "dpop_proof_expired",
		"dpop_proof_replayed", "dpop_key_mismatch", "dpop_foreign_origin", "dpop_required",
		"authorization_pending", "slow_down", "scim_unsupported",
	}
}

func (handler *SesameErrorHandler) unauthorizedCodes() []string {
	return []string{"session_rejected", "session_inactive", "actor_session_invalid", handler.bearerRefusalCode()}
}

func (handler *SesameErrorHandler) forbiddenCodes() []string {
	return []string{
		"tenant_mismatch", "actor_tenant_mismatch", "access_denied", "provisioning_forbidden",
		"reauthentication_required",
		"client_disabled", "consent_required", "subject_not_linked", "saml_subject_not_linked",
	}
}

func (handler *SesameErrorHandler) notFoundCodes() []string {
	return []string{
		"tenant_not_found", "principal_not_found", "role_not_found", "grant_not_found",
		"group_not_found", "group_member_not_found", "transaction_not_found", "session_not_found",
		"client_not_found", "interaction_not_found", "refresh_family_not_found", "consent_not_found",
		"passkey_not_found", "device_authorization_not_found", "user_code_not_found",
		"request_uri_not_found", "provider_not_found", "federated_login_not_found",
		"provisioning_client_not_found", "scim_user_not_found", "scim_group_not_found",
		"saml_provider_not_found", "saml_login_not_found",
	}
}

func (handler *SesameErrorHandler) conflictCodes() []string {
	return []string{
		"identifier_conflict", "role_exists", "grant_exists", "group_exists", "group_member_exists",
		"client_exists", "passkey_exists", "totp_already_active", "totp_not_enrolled",
		"stale_policy_version", "request_uri_conflict", "scim_user_conflict", "transaction_closed",
		"interaction_closed", "federated_login_closed", "provider_not_configured",
	}
}

func (handler *SesameErrorHandler) unavailableCodes() []string {
	return []string{"engine_busy"}
}
