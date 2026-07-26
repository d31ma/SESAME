const TITLE = 'Reason and error codes — SESAME'
document.title = TITLE

// Every code here is asserted against the engine's own constants by
// test/contract/website_test.go: a code the engine does not define fails the
// build, and so does a code the engine defines that this page never mentions.
// A stale reference is worse than none, because a developer branches on it.

const REASONS = [
  { code: 'allow_role_grant', meaning: 'A role granted directly to the principal matched.' },
  { code: 'allow_group_grant', meaning: 'A role granted to a group the principal belongs to matched.' },
  { code: 'deny_no_grant', meaning: 'No applicable grant. This is the default answer, and also what a supplied-but-non-matching condition produces.' },
  { code: 'deny_principal_suspended', meaning: 'The principal exists but is suspended. Checked before any grant.' },
  { code: 'deny_principal_not_found', meaning: 'No such principal in this tenant.' },
  { code: 'deny_tenant_not_found', meaning: 'No such tenant.' },
  { code: 'deny_missing_context', meaning: 'A condition needed an attribute the request did not supply. Names the attribute only when every supplied value already matched — otherwise naming it would be false advice.' },
  { code: 'deny_session_invalid', meaning: 'A session was supplied instead of a principal, and it is expired, revoked, or unknown. Never falls back to a lower assurance.' },
]

const GROUPS = [
  {
    title: 'Transport and protocol',
    note: 'Raised by the machine protocol itself, before any operation runs.',
    codes: [
      { code: 'invalid_json', meaning: 'The request line was not a JSON object.' },
      { code: 'unsupported_protocol', meaning: 'The request named a protocol version this engine does not speak.' },
      { code: 'operation_not_found', meaning: 'This build does not route that operation. Usually a version mismatch; call RequireOperations at startup to find out sooner.' },
      { code: 'frame_too_large', meaning: 'The request exceeded the 1 MiB frame limit.' },
      { code: 'internal_error', meaning: 'An unexpected failure. Retryable only if the error says so.' },
    ],
  },
  {
    title: 'Configuration',
    note: 'The engine is running but cannot serve this operation. Every one of these fails closed rather than guessing.',
    codes: [
      { code: 'storage_not_configured', meaning: 'No deployment or FYLO root. Set SESAME_DEPLOYMENT, or FYLO_BINARY and FYLO_ROOT together.' },
      { code: 'signing_not_configured', meaning: 'Token issuance needs the deployment signing key.' },
      { code: 'issuer_not_configured', meaning: 'Token issuance needs an issuer. Pass --issuer to sesame init.' },
      { code: 'secrets_not_configured', meaning: 'Sealing needs the deployment secrets key. TOTP enrolment cannot proceed without it.' },
      { code: 'relying_party_not_configured', meaning: 'Passkeys need a relying-party identifier and origin.' },
    ],
  },
  {
    title: 'Tenants, principals, and identifiers',
    note: '',
    codes: [
      { code: 'tenant_not_found', meaning: 'No such tenant.' },
      { code: 'principal_not_found', meaning: 'No such principal, or it belongs to another tenant.' },
      { code: 'identifier_conflict', meaning: 'That normalised identifier is already claimed in this tenant. Claims are atomic, so exactly one concurrent creation wins.' },
    ],
  },
  {
    title: 'Roles, grants, and groups',
    note: '',
    codes: [
      { code: 'role_exists', meaning: 'A role with that name already exists in the tenant.' },
      { code: 'role_not_found', meaning: 'No such role.' },
      { code: 'grant_exists', meaning: 'That role is already granted to that subject.' },
      { code: 'grant_not_found', meaning: 'No such grant.' },
      { code: 'group_exists', meaning: 'A group with that name already exists in the tenant.' },
      { code: 'group_not_found', meaning: 'No such group.' },
      { code: 'group_member_exists', meaning: 'That principal is already a member.' },
      { code: 'group_member_not_found', meaning: 'That principal is not a member.' },
      { code: 'stale_policy_version', meaning: 'A pinned policy version is older than the engine can still answer for.' },
    ],
  },
  {
    title: 'Authentication and sessions',
    note: 'Note what is absent: there is no "unknown identifier" code, because beginning a login succeeds either way.',
    codes: [
      { code: 'transaction_not_found', meaning: 'No such authentication transaction, or it belongs to another tenant.' },
      { code: 'transaction_closed', meaning: 'The transaction is completed, failed, or out of attempts. Start a new one.' },
      { code: 'session_not_found', meaning: 'No such session.' },
      { code: 'session_inactive', meaning: 'The session is expired or revoked.' },
      { code: 'totp_not_enrolled', meaning: 'The principal has no activated TOTP authenticator.' },
      { code: 'totp_already_active', meaning: 'TOTP is already activated for this principal.' },
      { code: 'totp_invalid_code', meaning: 'The code is wrong, outside its window, or already spent. A spent code fails here even though it was valid moments ago.' },
      { code: 'passkey_exists', meaning: 'That credential is already registered.' },
      { code: 'passkey_not_found', meaning: 'No such passkey.' },
      { code: 'passkey_challenge_expired', meaning: 'The registration or assertion challenge is no longer current.' },
      { code: 'passkey_rejected', meaning: 'The assertion failed verification, including a sign counter that went backwards — which indicates a cloned authenticator.' },
    ],
  },
  {
    title: 'OIDC clients and tokens',
    note: '',
    codes: [
      { code: 'client_exists', meaning: 'A client with that name already exists in the tenant.' },
      { code: 'client_not_found', meaning: 'No such client.' },
      { code: 'client_disabled', meaning: 'The client is disabled. Disablement is immediate and durable.' },
      { code: 'invalid_redirect_uri', meaning: 'The redirect URI is not an exact registered match. Prefix and wildcard matching are not supported, deliberately.' },
      { code: 'scope_not_allowed', meaning: 'The request asked for a scope the client is not registered for.' },
      { code: 'consent_required', meaning: 'A third-party client needs recorded consent before it receives a code.' },
      { code: 'consent_not_found', meaning: 'No standing consent for that principal and client.' },
      { code: 'interaction_not_found', meaning: 'No such interaction.' },
      { code: 'interaction_closed', meaning: 'The interaction is spent or expired.' },
      { code: 'invalid_grant', meaning: 'Every token-exchange failure, undifferentiated on purpose.' },
      { code: 'refresh_family_not_found', meaning: 'No such refresh-token family.' },
      { code: 'authorization_pending', meaning: "The device grant's user has not approved it yet. This is the only outcome that invites another poll; RFC 8628 spells it this way, so device libraries branch on it." },
      { code: 'slow_down', meaning: 'The device is polling faster than the interval it was issued. Add five seconds and keep going — guidance, not a refusal.' },
      { code: 'access_denied', meaning: 'The device authorization was refused, expired, or ran out of user-code attempts. One code for all three, so a device cannot probe the verification surface through the token endpoint.' },
      { code: 'device_authorization_not_found', meaning: 'No such device authorization.' },
      { code: 'user_code_not_found', meaning: 'No pending device authorization for that user code, including one whose attempts are spent.' },
      { code: 'dpop_proof_invalid', meaning: 'The DPoP proof is malformed: not a compact JWS, the wrong typ, an algorithm other than ES256, a key that is not a public P-256 point, or a signature that does not verify.' },
      { code: 'dpop_proof_not_bound', meaning: 'The proof names a different HTTP method or URI than the one the host says it served, or its ath is for a different access token. A proof is good for one request and one token.' },
      { code: 'dpop_proof_expired', meaning: 'The proof\u2019s iat is outside its one-minute window, in either direction. A future-dated proof is refused as firmly as a stale one \u2014 a fast clock would otherwise mint proofs valid long after the moment they were meant for.' },
      { code: 'dpop_proof_replayed', meaning: 'This proof identifier has already been used. The one DPoP failure that means something is wrong rather than that something is broken.' },
      { code: 'dpop_key_mismatch', meaning: 'The proof is signed by a key other than the one the token is bound to \u2014 a valid proof, presented with somebody else\u2019s token.' },
      { code: 'dpop_foreign_origin', meaning: 'The proof names a URI outside this deployment\u2019s issuer origin. This is the one binding check the engine makes without trusting the host, so a proof minted for another authorization server is refused even by a host that reported it faithfully.' },
      { code: 'dpop_required', meaning: 'A key-bound refresh token was presented without a proof. Fail closed: a bound token used as a bearer token is exactly the theft the binding exists to catch.' },
      { code: 'request_uri_not_found', meaning: 'The request_uri is unknown, expired, already spent, or belongs to another client. One code for all four: a pushed reference that told a caller which of those it was would be a probe of somebody else\u2019s requests.' },
      { code: 'request_uri_conflict', meaning: 'An authorization request carried both a request_uri and loose parameters. RFC 9126 forbids merging them, and SESAME refuses rather than ignores, so a client finds out instead of silently getting the pushed values.' },
      { code: 'invalid_logout_hint', meaning: 'The id_token_hint is missing, malformed, or not one this deployment issued.' },
      { code: 'invalid_post_logout_redirect_uri', meaning: 'The post-logout redirect URI is not registered for that client.' },
    ],
  },
  {
    title: 'Federation, SCIM, and SAML',
    note: 'The two assertion codes cover every cause; the specific reason goes to the audit ledger.',
    codes: [
      { code: 'provider_not_found', meaning: 'Unknown, disabled, or cross-tenant OIDC provider.' },
      { code: 'provider_not_configured', meaning: 'The provider has no validated metadata yet. Fetch its discovery document first.' },
      { code: 'provider_document_rejected', meaning: 'A discovery document or key set failed validation.' },
      { code: 'federated_login_not_found', meaning: 'Unknown or cross-tenant federated login.' },
      { code: 'federated_login_closed', meaning: 'That federated login is already spent.' },
      { code: 'federated_login_expired', meaning: 'That federated login has expired.' },
      { code: 'subject_not_linked', meaning: 'A verified assertion for a subject no principal claims, under strict linking.' },
      { code: 'assertion_rejected', meaning: 'An inbound OIDC assertion failed verification.' },
      { code: 'provisioning_client_not_found', meaning: 'Unknown SCIM client or bearer token.' },
      { code: 'provisioning_denied', meaning: 'The SCIM bearer token is missing, wrong, or belongs to a disabled client.' },
      { code: 'provisioning_forbidden', meaning: 'The SCIM client is not granted the capability it used, such as group management.' },
      { code: 'scim_user_not_found', meaning: 'No such provisioned user.' },
      { code: 'scim_user_conflict', meaning: 'That userName is already provisioned.' },
      { code: 'scim_group_not_found', meaning: 'No such provisioned group.' },
      { code: 'scim_unsupported', meaning: 'A SCIM feature this engine does not implement, such as a value-path PATCH filter.' },
      { code: 'saml_provider_not_found', meaning: 'Unknown, disabled, or cross-tenant SAML provider.' },
      { code: 'saml_login_not_found', meaning: 'Unknown, closed, expired, or cross-tenant SAML login.' },
      { code: 'saml_subject_not_linked', meaning: 'A verified assertion for a subject no principal claims, under strict linking.' },
      { code: 'saml_assertion_rejected', meaning: 'A SAML assertion failed verification.' },
    ],
  },
  {
    title: 'Request validation',
    note: '',
    codes: [
      { code: 'invalid_request', meaning: 'A parameter is missing, malformed, or out of range. The message describes the parameter and never a credential.' },
    ],
  },
]

export default class extends Tac {
  reasons = REASONS
  groups = GROUPS

  constructor(props = {}, tac = undefined) {
    super(props, tac)
    if (this.isBrowser) document.title = TITLE
  }
}
