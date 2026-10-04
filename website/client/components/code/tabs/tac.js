// Go snippets for the guides, keyed by flow.
//
// Every sequence here was executed against a real compiled engine and a real
// FYLO runtime before it was written down, including the outputs shown in
// comments. A guide that teaches a call the engine does not accept is worse
// than no guide. `test/contract/website_test.go` resolves every method named
// here against the Go package in server/packages. Over HTTP, each call is the
// Yon route of the same operation (docs/YON.md).
export const LANGUAGES = ["Go"]

const FLOWS = {
  "password-login": {
    "Go": "tx, err := client.AuthenticationBegin(ctx, tenantID,\n    sesame.PrincipalIdentifier{Namespace: \"email\", Value: \"alice@example.com\"})\n\n// begin succeeds whether or not the identifier resolves, so it\n// never reveals which accounts exist. Only a verified factor\n// tells the two apart.\nstate, err := client.AuthenticationVerifyPassword(ctx, tx.TransactionID, password)\n// {\"state\": \"awaiting_factor\", \"assurance\": \"password\", \"attempts_left\": 4}\n\nsession, err := client.AuthenticationComplete(ctx, tx.TransactionID, time.Hour)\n// {\"session_id\": \"ses_...\", \"session_secret\": \"...\",\n//   \"assurance\": \"password\", \"expires_at\": \"2026-07-26T16:42:36Z\"}\n\n// session_secret is returned exactly once. Store the pair the way\n// you would a session cookie; SESAME keeps only a digest of it.",
  },
  "session": {
    "Go": "// Verify on every request. This is the one session-usability rule\n// the OIDC flow and step-up decisions both go through.\nverified, err := client.SessionVerify(ctx, session.SessionID, session.Secret)\n// {\"principal_id\": \"prn_...\", \"assurance\": \"password\", \"expires_at\": \"...\"}\n\n// Revocation is durable and immediate: it survives a restart, and\n// it also revokes every refresh-token family issued on this session.\nclient.SessionRevoke(ctx, session.SessionID, \"signed out\")",
  },
  "totp": {
    "Go": "// 1. Enrol. The secret is returned once; render the URI as a QR code.\nenrolled, err := client.TOTPEnroll(ctx, principalID, \"Example App\")\n// {\"secret\": \"...\", \"provisioning_uri\": \"otpauth://totp/Example%20App:...\"}\n\n// 2. Activate by proving an authenticator app holds it. Until this\n// succeeds the factor does not exist, so a half-finished enrolment\n// cannot lock anyone out.\nclient.TOTPActivate(ctx, principalID, codeFromTheApp)\n\n// 3. At login, after the password.\ntx, err := client.AuthenticationBegin(ctx, tenantID,\n    sesame.PrincipalIdentifier{Namespace: \"email\", Value: \"alice@example.com\"})\nclient.AuthenticationVerifyPassword(ctx, tx.TransactionID, password)\nstate, err := client.AuthenticationVerifyTOTP(ctx, tx.TransactionID, codeFromTheApp)\n// {\"state\": \"awaiting_factor\", \"assurance\": \"mfa\", \"attempts_left\": 3}\n\n// The session completed from this transaction carries assurance \"mfa\".",
  },
  "recovery": {
    "Go": "// Ten single-use codes, returned once, stored only as digests.\n// Reissuing retires the previous set, so a leaked list is revoked\n// by handing out a new one rather than by deleting anything.\nissued, err := client.RecoveryCodesIssue(ctx, principalID)\n\n// At login, in place of the second factor.\ntx, err := client.AuthenticationBegin(ctx, tenantID,\n    sesame.PrincipalIdentifier{Namespace: \"email\", Value: \"alice@example.com\"})\nclient.AuthenticationVerifyPassword(ctx, tx.TransactionID, password)\nstate, err := client.AuthenticationVerifyRecoveryCode(ctx, tx.TransactionID, issued.Codes[0])\n// {\"assurance\": \"mfa\", \"attempts_left\": 3}\n\n// That code is now spent — durably, so a restart cannot revive it.",
  },
  "decide": {
    "Go": "// Default deny: without a matching grant this is a refusal.\ndecision, err := client.Decide(ctx, sesame.DecisionRequest{\n    TenantID:    tenantID,\n    PrincipalID: principalID,\n    Action:      \"doc:read\",\n    Resource:    \"project:alpha\",\n}, nil)\n\n// decision.Decision == \"deny\", decision.ReasonCode == \"deny_no_grant\"",
  },
  "session-to-jwt": {
    "Go": "raw := make([]byte, 48)\nif _, err := rand.Read(raw); err != nil {\n    return err\n}\nverifier := base64.RawURLEncoding.EncodeToString(raw)\nsum := sha256.Sum256([]byte(verifier))\nchallenge := base64.RawURLEncoding.EncodeToString(sum[:])\n\n// 1. Your /authorize route. The whole request is validated here,\n//    before anyone is shown a login form.\n\ninteraction, err := client.Authorize(ctx, sesame.AuthorizationRequest{\n    ClientID:            clientID,\n    RedirectURI:         \"https://app.example.com/cb\",\n    ResponseType:        \"code\",\n    Scopes:              []string{\"profile\", \"offline_access\"},\n    State:               state,\n    Nonce:               nonce,\n    CodeChallenge:       challenge,\n    CodeChallengeMethod: \"S256\",\n})\n\n// 2. Authenticate however you like, then prove it. This is the only\n//    place a session becomes an authorization code.\n\ndone, err := client.InteractionComplete(ctx, interaction.InteractionID,\n    interaction.Secret, session.SessionID, session.Secret)\n\n// 3. Your /token route exchanges the code. PKCE is mandatory.\n\ntokens, err := client.TokenExchange(ctx, sesame.TokenRequest{\n    GrantType:    \"authorization_code\",\n    Code:         done.Code,\n    RedirectURI:  \"https://app.example.com/cb\",\n    ClientID:     clientID,\n    ClientSecret: clientSecret,\n    CodeVerifier: verifier,\n})\n// tokens.AccessToken, tokens.IDToken, tokens.RefreshToken",
  },
  "device-grant": {
    "Go": "// 1. The device asks. It has no browser, so it gets two codes:\n// one it keeps, one a person reads off the screen.\nstarted, err := client.DeviceAuthorizationStart(ctx, clientID, []string{\"profile\"})\n// {\"device_code\": \"...\", \"user_code\": \"HKMP-TVWX\", \"interval\": 5,\n//   \"expires_in\": 600}\n\n// 2. On a phone, your own page shows what is being asked for.\npending, err := client.DeviceAuthorizationLookup(ctx, tenantID, typedCode)\n// {\"client_name\": \"living-room-tv\", \"scopes\": [\"openid\", \"profile\"]}\n\n// 3. Approval proves a SESSION, not a principal. A caller that could\n// merely name a principal could attach any device to anyone.\n_, err = client.DeviceAuthorizationApprove(ctx, tenantID, typedCode,\n    session.SessionID, session.Secret)\n\n// 4. Meanwhile the device polls. Only authorization_pending invites\n// another poll; slow_down means add five seconds; access_denied\n// covers refused, expired, and never-existed alike.\ntokens, err := client.TokenExchange(ctx, sesame.TokenRequest{\n    GrantType:  \"urn:ietf:params:oauth:grant-type:device_code\",\n    DeviceCode: started[\"device_code\"].(string),\n    ClientID:   clientID,\n})",
  },
  "pushed-authorization": {
    "Go": "// Push the whole request on the back channel, authenticated as the\n// client. Nothing about it travels through the browser.\npushed, err := client.PushedAuthorizationStart(ctx, sesame.AuthorizationRequest{\n    ClientID:            clientID,\n    RedirectURI:         \"https://app.example/cb\",\n    ResponseType:        \"code\",\n    Scopes:              []string{\"profile\"},\n    State:               state,\n    Nonce:               nonce,\n    CodeChallenge:       challenge,\n    CodeChallengeMethod: \"S256\",\n}, clientSecret)\n// {\"request_uri\": \"urn:ietf:params:oauth:request_uri:par_...\",\n//   \"expires_in\": 90}\n\n// Redeeming it takes the reference and NOTHING else. Any other field\n// set here is refused with request_uri_conflict \u2014 merging them would\n// restore exactly the tampering the push removed.\nstarted, err := client.Authorize(ctx, sesame.AuthorizationRequest{\n    ClientID:   clientID,\n    RequestURI: pushed.RequestURI,\n})",
  },
  "dpop": {
    "Go": "// Your client mints a proof per request with its own P-256 key.\n// SESAME never sees the private half.\nproof := signDPoPProof(key, jti, \"POST\", \"https://id.example/oauth/token\")\n\ntokens, err := client.TokenExchange(ctx, sesame.TokenRequest{\n    GrantType:    \"authorization_code\",\n    Code:         code,\n    RedirectURI:  redirectURI,\n    ClientID:     clientID,\n    ClientSecret: clientSecret,\n    CodeVerifier: verifier,\n    DPoPProof:    proof,\n    // The engine speaks no HTTP. These are YOUR assertion about the\n    // request you served \u2014 report them faithfully or the binding\n    // decides nothing.\n    DPoPMethod: \"POST\",\n    DPoPURI:    \"https://id.example/oauth/token\",\n})\n// tokens.TokenType == \"DPoP\", not \"Bearer\".\n\n// At the resource, check the token against a fresh proof.\nverified, err := client.DPoPVerify(ctx, tokens.AccessToken, requestProof,\n    \"GET\", \"https://id.example/api/invoices\")\n// {Active: true, PrincipalID: \"prn_...\", Thumbprint: \"...\"}",
  },
  "step-up": {
    "Go": "// Pass the session instead of a principal. The engine verifies it and\n// derives context under the reserved \"session.\" prefix, so a caller cannot\n// assert its own assurance level.\ndecision, err := client.Decide(ctx, sesame.DecisionRequest{\n    TenantID:      tenantID,\n    SessionID:     session.SessionID,\n    SessionSecret: session.Secret,\n    Action:        \"billing:change\",\n    Resource:      \"account:acme\",\n}, nil)\n// A permission conditioned on session.assurance == \"mfa\" denies a\n// password-only session with ReasonCode \"deny_no_grant\".",
  },
}

export default class extends Tac {
  // Overridden by the `flow` attribute on the tag.
  flow = 'password-login'
  languages = LANGUAGES
  active = LANGUAGES[0]

  get snippet() {
    const set = FLOWS[this.flow]
    return set ? set[this.active] || '' : ''
  }

  select(language) {
    this.active = language
  }
}
