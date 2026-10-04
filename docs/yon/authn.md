# Authentication Routes

This page lists the Yon routes for signing in, managing authenticators,
sessions and the signing key set. It extends the route table in
[the Yon operator guide](../YON.md). Every route is `POST`, takes a JSON body
and answers JSON. Errors answer `{"code":"<code>"}` with the statuses in the
guide.

Secrets (passwords, TOTP codes and secrets, recovery codes, session secrets)
travel only in request bodies, response bodies and the `Sesame-Session`
header. They never appear in a path or query string, and neither `ty` nor the
controllers log them. When `ty` refuses a body as malformed (`400`), its answer
names the field path or the model, never the submitted value.

## Who may call each route

"The caller" is the principal of the session in the `Sesame-Session` header.

| Route | Operation | Who may call | Acts on |
| --- | --- | --- | --- |
| `POST /api/v1/authn/begin` | `authn.begin` | anyone | a new login transaction |
| `POST /api/v1/authn/verify-password` | `authn.verify_password` | anyone holding the transaction ID | that transaction |
| `POST /api/v1/authn/verify-totp` | `authn.verify_totp` | anyone holding the transaction ID | that transaction |
| `POST /api/v1/authn/verify-recovery-code` | `authn.verify_recovery_code` | anyone holding the transaction ID | that transaction |
| `POST /api/v1/authn/passkey-options` | `authn.passkey_options` | anyone holding the transaction ID | that transaction |
| `POST /api/v1/authn/verify-passkey` | `authn.verify_passkey` | anyone holding the transaction ID | that transaction |
| `POST /api/v1/authn/complete` | `authn.complete` | anyone holding the transaction ID | that transaction |
| `POST /api/v1/session/verify` | `session.verify` | anyone holding the session ID and secret | that session |
| `POST /api/v1/session/revoke` | `session.revoke` | a signed-in caller | the caller's current session only |
| `POST /api/v1/session/revoke-by-id` | `session.revoke` of any session | an administrator | the caller is sent as the request's actor; SESAME refuses a live session of another tenant with `403 {"code":"actor_tenant_mismatch"}` and revokes nothing |
| `POST /api/v1/authenticator/set-password` | `authenticator.set_password` | a signed-in caller | the caller only |
| `POST /api/v1/authenticator/totp-enroll` | `authenticator.totp_enroll` | a signed-in caller | the caller only |
| `POST /api/v1/authenticator/totp-activate` | `authenticator.totp_activate` | a signed-in caller | the caller only |
| `POST /api/v1/authenticator/recovery-codes-issue` | `authenticator.recovery_codes_issue` | a signed-in caller | the caller only |
| `POST /api/v1/authenticator/passkey-register-begin` | `authenticator.passkey_register_begin` | a signed-in caller | the caller only |
| `POST /api/v1/authenticator/passkey-register-finish` | `authenticator.passkey_register_finish` | a signed-in caller | the caller only |
| `POST /api/v1/authenticator/passkey-list` | `authenticator.passkey_list` | a signed-in caller | the caller only |
| `POST /api/v1/authenticator/passkey-remove` | `authenticator.passkey_remove` | a signed-in caller | a passkey of the caller only |
| `POST /api/v1/authenticator/set-password-for-principal` | `authenticator.set_password` | an administrator | a principal in the administrator's tenant |
| `POST /api/v1/authenticator/passkey-list-for-principal` | `authenticator.passkey_list` | an administrator | a principal in the administrator's tenant |
| `POST /api/v1/authenticator/passkey-remove-for-principal` | `authenticator.passkey_remove` | an administrator | a passkey of a principal in the administrator's tenant |
| `POST /api/v1/token/jwks` | `token.jwks` | anyone | the public signing key set |

### Login steps are public

A login step runs before the caller has a session, so every `authn` route is
public. The engine's login state machine stays the only authority: the routes
pass the body through unchanged and add no state of their own.

- The transaction ID is 128 random bits and acts as the handle for one login.
  Treat it as confidential for the ten minutes it lives.
- `authn.begin` answers the same for a known and an unknown identifier.
- A wrong password, a wrong or replayed TOTP code, a spent recovery code and a
  passkey assertion that does not verify are not errors: the step answers
  `200` with the transaction state, spends one of the five attempts and keeps
  the assurance where it was.
- A step after the transaction is closed, completed, out of attempts or out of
  order (a second factor before the first, `complete` before any factor)
  answers `409 {"code":"transaction_closed"}`. Completing twice answers `409`.
- An unknown transaction answers `404 {"code":"transaction_not_found"}`; a
  malformed one answers `400 {"code":"invalid_request"}`.
- `authn.complete` returns the session secret once. Send it back only in the
  `Sesame-Session: <session_id>:<session_secret>` header.

### Session routes

`session/verify` is public because the session secret in the body is the proof.
A wrong secret and an unknown session answer the same
`404 {"code":"session_not_found"}`; an expired or revoked session answers
`401 {"code":"session_inactive"}` only to a holder of the right secret. The
answer never contains the secret or its digest.

`session/revoke` ends the caller's current session (sign out). Its body is
`{"reason":"..."}` or `{}`; it cannot name another session.

`session/revoke-by-id` lets an administrator end any session of their tenant,
for example a stolen one. Its body is `{"session_id":"...","reason":"..."}`.
SESAME cannot report a session's tenant without its secret, so the host does
not check the tenant itself. Instead, every route that acts for a signed-in
caller sends that caller as the request's actor (see
[ADR 0007](../adr/0007-sesame-ships-a-yon-host-project.md)), and SESAME refuses
to write an event into another tenant: `403 {"code":"actor_tenant_mismatch"}`,
with nothing revoked, whether that session is live or already revoked. An
unknown session answers `404 {"code":"session_not_found"}`.

### Self-service authenticator routes

The body of a self-service route has no `principal_id`. The controller takes
the principal from the caller's session, so a caller can only ever change its
own authenticators. A body that adds `principal_id` is refused by `ty` with
`400` before the route runs. Routes without a body (`recovery-codes-issue`,
`passkey-register-begin`, `passkey-list`) ignore any body they receive.

`passkey-remove` first lists the caller's passkeys and refuses a credential
that is not among them with `404 {"code":"passkey_not_found"}`, byte for byte
the answer for a credential that does not exist, so a caller cannot learn other
principals' credential IDs.

### Recent sign-in for authenticator changes

Every self-service route that changes an authenticator (`set-password`,
`totp-enroll`, `totp-activate`, `recovery-codes-issue`,
`passkey-register-begin`, `passkey-register-finish`, `passkey-remove`) needs a
session issued in the last 10 minutes. The host reads the session's
`issued_at` from `session.verify`; the engine sets it once, when the session is
issued at sign-in, and never refreshes it. An older session answers
`403 {"code":"reauthentication_required"}` before anything changes: sign in
again and retry with the new session. `passkey-list` and `session/revoke`
work with any valid session. The window is fixed at 10 minutes and has no
setting.

`totp-enroll` and `recovery-codes-issue` return their secrets exactly once.
Passkey routes need a deployment created with `sesame init --issuer`; without
one they answer `500 {"code":"internal_error"}` (the engine reports
`relying_party_not_configured`).

### Administrator routes

An operation that a principal may run on itself and an administrator may run
on someone else has two routes: the self-service route above, and a
`-for-principal` route whose body names the target with `principal_id`. The
`-for-principal` routes need the `Administrator` role (`403` otherwise). The
host loads the named principal first and answers
`403 {"code":"tenant_mismatch"}` when it belongs to another tenant, so an
administrator never reaches another tenant.

- `set-password-for-principal` takes `{"principal_id","password"}`: a password
  reset. The administrator chooses the new password; tell the principal to
  change it.
- `passkey-list-for-principal` takes `{"principal_id"}`.
- `passkey-remove-for-principal` takes `{"principal_id","credential_id"}` and
  removes the passkey only when it belongs to that principal; otherwise
  `404 {"code":"passkey_not_found"}`. It is the lost-device response.

The administrator routes do not apply the recent sign-in rule: the
administrator's session is already held to the `Administrator` role, decided
by the engine for every request.

## Not routed

| Operation | Why |
| --- | --- |
| `authenticator.totp_enroll`, `totp_activate`, `recovery_codes_issue`, `passkey_register_begin`, `passkey_register_finish` for another principal | An administrator must never receive another principal's factor secrets. Use the command line. |

## Known gaps

- **Recent sign-in is not proof of the current credential.** A session secret
  stolen within 10 minutes of sign-in can still change the password or add a
  passkey, and no route asks for the current password first. The engine has
  no reauthentication primitive for `authenticator.*`, so the host does not
  invent one. Closing this needs an engine operation (for example,
  authenticator changes that require a freshly verified login transaction).
  Keep session lifetimes short and revoke sessions on suspicion.
- **No throttling of public login steps.** Each transaction allows five
  attempts and every engine start is serialized, but nothing limits how many
  transactions a client may begin. Put a rate limit in front of `ty`
  (reverse proxy) for `/api/v1/authn/*`.
- **Login transaction expiry** (ten minutes) is enforced by the engine and
  covered by its tests; the Yon tests cannot move the engine's clock.
