package host

// RedirectNotAllowedError reports a login-start whose SAML consumer URL or
// federation redirect URI is not exactly one of the operator's allowlisted
// URLs (sesame.samlconsumerurls, sesame.federationredirecturis). The host
// refuses before SESAME runs.
type RedirectNotAllowedError struct{}

func (failure *RedirectNotAllowedError) Error() string {
	return "the redirect or consumer URL is not in the operator's allowlist " +
		"(sesame.samlconsumerurls / sesame.federationredirecturis)"
}

// ErrorCode returns redirect_not_allowed.
func (failure *RedirectNotAllowedError) ErrorCode() string {
	return "redirect_not_allowed"
}
