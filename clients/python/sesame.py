"""A thin Python client for a local SESAME process.

The client owns process lifecycle, NDJSON framing, and typed transport
errors. Identity and authorization semantics remain in the SESAME executable.
Dependencies: Python standard library only.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import subprocess
import threading
from typing import Any

PROTOCOL_VERSION = "1"

# Bounds what a failing engine can make the caller hold: generous enough for a
# refusal and its remedy, short of anything worth worrying about.
STARTUP_DIAGNOSTICS_BYTES = 4096
MAX_FRAME_BYTES = 1 << 20
CLOSE_TIMEOUT_SECONDS = 2.0

__all__ = ["Client", "ProtocolError"]


class ProtocolError(Exception):
    """A stable error returned by the SESAME machine interface."""

    def __init__(self, error: dict[str, Any]) -> None:
        self.code = error.get("code", "")
        self.retryable = bool(error.get("retryable", False))
        self.details = error.get("details")
        super().__init__(f"sesame protocol error {self.code}: {error.get('message', '')}")


class IncompatibleEngineError(RuntimeError):
    """A SESAME binary this client cannot speak to.

    It names both sides, because the fix is always to change one of them.
    """

    def __init__(
        self,
        client_protocol_version: str,
        engine_protocol_version: str,
        engine_version: str,
        missing_operations: list[str] | None = None,
    ) -> None:
        self.client_protocol_version = client_protocol_version
        self.engine_protocol_version = engine_protocol_version
        self.engine_version = engine_version
        self.missing_operations = missing_operations or []
        if engine_protocol_version != client_protocol_version:
            message = (
                f"sesame engine {engine_version} speaks machine protocol "
                f'"{engine_protocol_version}"; this client speaks "{client_protocol_version}"'
            )
        else:
            message = (
                f"sesame engine {engine_version} does not support "
                f"{len(self.missing_operations)} operation(s) this client requires: "
                + ", ".join(self.missing_operations)
            )
        super().__init__(message)


class Client:
    """Owns one long-lived local SESAME subprocess."""

    def __init__(
        self,
        # SESAME_BINARY names the engine when no option does; an explicit option still wins.
        binary: str = "",
        *,
        deployment: str | None = None,
        fylo_binary: str | None = None,
        fylo_root: str | None = None,
        skip_compatibility_check: bool = False,
    ) -> None:
        arguments = [binary or os.environ.get("SESAME_BINARY") or "sesame", "exec", "--loop"]
        if deployment:
            arguments += ["--deployment", deployment]
        if fylo_binary or fylo_root:
            arguments += ["--fylo-binary", fylo_binary or "", "--fylo-root", fylo_root or ""]
        self._process = subprocess.Popen(  # noqa: S603 - explicit operator-supplied binary
            arguments,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            # The startup window of stderr is captured so a refusal can
            # explain itself: the engine reports a missing deployment or an
            # unusable FYLO root this way and then exits, and discarding it
            # would leave the caller with a dead process and no reason.
            stderr=subprocess.PIPE,
            # Windows consoles default to the ANSI code page.
            encoding="utf-8",
            errors="strict",
        )
        self._closed = False
        # A mismatched engine is found here rather than partway through a
        # security flow that then cannot finish. system.version needs no
        # storage, so this works before a FYLO root is configured.
        if not skip_compatibility_check:
            try:
                self.check_compatibility()
            except BaseException as error:
                diagnostic = self._startup_diagnostics()
                self.close()
                if diagnostic:
                    raise type(error)(f"{error}: {diagnostic}") from error
                raise
        # The engine is up; its diagnostics are the host's business from here,
        # and an undrained pipe would eventually block the child.
        self._release_stderr()

    def _startup_diagnostics(self) -> str:
        """Reads what a failing engine said before it exited."""
        stream = self._process.stderr
        if stream is None:
            return ""
        try:
            return stream.read(STARTUP_DIAGNOSTICS_BYTES).strip()
        except OSError:
            return ""

    def _release_stderr(self) -> None:
        """Drains diagnostics in the background so the child never blocks."""
        stream = self._process.stderr
        if stream is None:
            return
        threading.Thread(target=stream.read, daemon=True).start()

    def check_compatibility(self) -> Any:
        """Fails unless the engine speaks this client's machine protocol."""
        version = self.version()
        if version.get("protocol_version") != PROTOCOL_VERSION:
            raise IncompatibleEngineError(
                PROTOCOL_VERSION,
                str(version.get("protocol_version")),
                str(version.get("version")),
            )
        return version

    def require_operations(self, *operations: str) -> Any:
        """Fails unless the engine routes every named operation.

        Call it at startup with what the application depends on: finding out
        here beats an operation_not_found in the middle of a login.
        """
        version = self.version()
        routed = set(version.get("operations") or [])
        missing = sorted(operation for operation in operations if operation not in routed)
        if missing:
            raise IncompatibleEngineError(
                PROTOCOL_VERSION,
                str(version.get("protocol_version")),
                str(version.get("version")),
                missing,
            )
        return version

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def request(self, operation: str, parameters: dict[str, Any] | None = None) -> Any:
        """Send one operation and return its result."""
        if self._closed:
            raise RuntimeError("sesame client is closed")

        request_id = secrets.token_hex(8)
        frame = json.dumps(
            {
                "protocol_version": PROTOCOL_VERSION,
                "request_id": request_id,
                "operation": operation,
                "parameters": parameters or {},
            },
            separators=(",", ":"),
        )
        if len(frame.encode("utf-8")) > MAX_FRAME_BYTES:
            raise ValueError("sesame request exceeds the maximum frame size")

        assert self._process.stdin is not None and self._process.stdout is not None
        self._process.stdin.write(frame + "\n")
        self._process.stdin.flush()

        line = self._process.stdout.readline()
        if not line:
            raise RuntimeError("sesame process exited")
        return _decode_response(request_id, line)

    # System
    def ping(self) -> Any:
        return self.request("system.ping")

    def version(self) -> Any:
        return self.request("system.version")

    def readiness(self) -> Any:
        return self.request("system.readiness")

    def set_password(self, principal_id: str, password: str) -> Any:
        """Stores a password verifier for a principal."""
        return self.request(
            "authenticator.set_password",
            {"principal_id": principal_id, "password": password},
        )

    def authn_begin(self, tenant_id: str, namespace: str, value: str) -> Any:
        """Starts a login transaction.

        Succeeds whether or not the identifier resolves, so the result never
        reveals which identifiers exist.
        """
        return self.request(
            "authn.begin",
            {
                "tenant_id": tenant_id,
                "identifier_namespace": namespace,
                "identifier_value": value,
            },
        )

    def authn_verify_password(self, transaction_id: str, password: str) -> Any:
        """Supplies a password to a running transaction."""
        return self.request(
            "authn.verify_password",
            {"transaction_id": transaction_id, "password": password},
        )

    def authn_complete(self, transaction_id: str, lifetime_seconds: int = 0) -> Any:
        """Issues a session for a satisfied transaction."""
        return self.request(
            "authn.complete",
            {"transaction_id": transaction_id, "lifetime_seconds": lifetime_seconds},
        )

    def recovery_codes_issue(self, principal_id: str) -> Any:
        """Generates a fresh recovery-code set, retiring any previous one."""
        return self.request(
            "authenticator.recovery_codes_issue", {"principal_id": principal_id}
        )

    def authn_verify_recovery_code(self, transaction_id: str, code: str) -> Any:
        """Spends one recovery code as a second factor."""
        return self.request(
            "authn.verify_recovery_code", {"transaction_id": transaction_id, "code": code}
        )

    def totp_enroll(self, principal_id: str, issuer: str = "SESAME") -> Any:
        """Issues a TOTP shared secret, returned exactly once."""
        return self.request(
            "authenticator.totp_enroll", {"principal_id": principal_id, "issuer": issuer}
        )

    def totp_activate(self, principal_id: str, code: str) -> Any:
        """Proves an enrollment and makes the factor usable."""
        return self.request(
            "authenticator.totp_activate", {"principal_id": principal_id, "code": code}
        )

    def authn_verify_totp(self, transaction_id: str, code: str) -> Any:
        """Supplies a TOTP code, raising the transaction's assurance to MFA."""
        return self.request(
            "authn.verify_totp", {"transaction_id": transaction_id, "code": code}
        )

    def session_verify(self, session_id: str, secret: str) -> Any:
        """Checks a presented session secret."""
        return self.request(
            "session.verify", {"session_id": session_id, "session_secret": secret}
        )

    def session_revoke(self, session_id: str, reason: str = "") -> Any:
        """Durably ends a session; repeating it is safe."""
        return self.request(
            "session.revoke", {"session_id": session_id, "reason": reason}
        )

    def metrics(self) -> Any:
        return self.request("system.metrics")

    # Tenants and administrators
    def tenant_bootstrap(self, name: str) -> Any:
        return self.request("tenant.bootstrap", {"name": name})

    def tenant_get_by_name(self, name: str) -> Any:
        return self.request("tenant.get", {"name": name})

    def tenant_get_by_id(self, tenant_id: str) -> Any:
        return self.request("tenant.get", {"tenant_id": tenant_id})

    def admin_bootstrap(self, tenant_name: str, namespace: str, value: str) -> Any:
        return self.request(
            "admin.bootstrap",
            {
                "tenant_name": tenant_name,
                "identifier_namespace": namespace,
                "identifier_value": value,
            },
        )

    # Principals
    def principal_create(self, tenant_id: str, kind: str, namespace: str, value: str) -> Any:
        return self.request(
            "principal.create",
            {
                "tenant_id": tenant_id,
                "kind": kind,
                "identifier_namespace": namespace,
                "identifier_value": value,
            },
        )

    def principal_get_by_id(self, principal_id: str) -> Any:
        return self.request("principal.get", {"principal_id": principal_id})

    def principal_get_by_identifier(self, tenant_id: str, namespace: str, value: str) -> Any:
        return self.request(
            "principal.get",
            {
                "tenant_id": tenant_id,
                "identifier_namespace": namespace,
                "identifier_value": value,
            },
        )

    def principal_suspend(self, principal_id: str) -> Any:
        return self.request("principal.suspend", {"principal_id": principal_id})

    # Authorization
    def role_create(self, tenant_id: str, name: str, permissions: list[dict[str, str]]) -> Any:
        return self.request(
            "role.create", {"tenant_id": tenant_id, "name": name, "permissions": permissions}
        )

    def group_create(self, tenant_id: str, name: str) -> Any:
        return self.request("group.create", {"tenant_id": tenant_id, "name": name})

    def group_member_add(self, group_id: str, principal_id: str) -> Any:
        return self.request(
            "group.member_add", {"group_id": group_id, "principal_id": principal_id}
        )

    def group_member_remove(self, group_id: str, principal_id: str) -> Any:
        return self.request(
            "group.member_remove", {"group_id": group_id, "principal_id": principal_id}
        )

    def grant_create(self, tenant_id: str, principal_id: str, role_id: str) -> Any:
        return self.request(
            "grant.create",
            {"tenant_id": tenant_id, "principal_id": principal_id, "role_id": role_id},
        )

    def grant_create_for_group(self, tenant_id: str, group_id: str, role_id: str) -> Any:
        return self.request(
            "grant.create", {"tenant_id": tenant_id, "group_id": group_id, "role_id": role_id}
        )

    def grant_revoke(self, grant_id: str) -> Any:
        return self.request("grant.revoke", {"grant_id": grant_id})

    def decide(self, request: dict[str, str], policy_version: int | None = None) -> Any:
        parameters = dict(request)
        if policy_version is not None:
            parameters["policy_version"] = policy_version
        return self.request("authorize.decide", parameters)

    def decide_batch(
        self, requests: list[dict[str, str]], policy_version: int | None = None
    ) -> Any:
        parameters: dict[str, Any] = {"requests": requests}
        if policy_version is not None:
            parameters["policy_version"] = policy_version
        return self.request("authorize.decide_batch", parameters)["decisions"]

    # ---- OIDC relying parties ------------------------------------------
    #
    # An omitted audience is treated as third party, the stricter rule: such
    # a client needs recorded user consent before it receives a code.
    def oidc_client_register(
        self,
        tenant_id: str,
        name: str,
        client_type: str,
        redirect_uris: list[str],
        scopes: list[str] | None = None,
        audience: str = "",
        post_logout_redirect_uris: list[str] | None = None,
    ) -> Any:
        return self.request(
            "oidc_client.register",
            {
                "tenant_id": tenant_id,
                "name": name,
                "client_type": client_type,
                "redirect_uris": redirect_uris,
                "scopes": scopes or [],
                "audience": audience,
                "post_logout_redirect_uris": post_logout_redirect_uris or [],
            },
        )

    def oidc_client_get(self, client_id: str) -> Any:
        return self.request("oidc_client.get", {"client_id": client_id})

    def oidc_client_rotate_secret(self, client_id: str) -> str:
        return self.request("oidc_client.rotate_secret", {"client_id": client_id})["client_secret"]

    def oidc_client_disable(self, client_id: str, reason: str = "") -> Any:
        return self.request("oidc_client.disable", {"client_id": client_id, "reason": reason})

    # ---- The external interaction contract -------------------------------
    #
    # authorize validates the whole request before anything is shown to a
    # user. The returned secret authorizes completing that one interaction.
    def authorize(self, request: dict[str, Any]) -> Any:
        return self.request("oidc.authorize", request)

    def interaction_get(self, interaction_id: str) -> Any:
        return self.request("oidc.interaction_get", {"interaction_id": interaction_id})

    def interaction_complete(
        self,
        interaction_id: str,
        interaction_secret: str,
        session_id: str,
        session_secret: str,
    ) -> Any:
        return self.request(
            "oidc.interaction_complete",
            {
                "interaction_id": interaction_id,
                "interaction_secret": interaction_secret,
                "session_id": session_id,
                "session_secret": session_secret,
            },
        )

    # A refresh response carries a new refresh token that replaces the one
    # presented; continuing to use the old one revokes the whole family.
    # The device grant (RFC 8628). device_authorize starts it; the person
    # types the user code elsewhere and approves or denies it there.
    def dpop_verify(
        self, access_token: str, proof: str, method: str, uri: str
    ) -> Any:
        """Checks a key-bound access token against a fresh proof (RFC 9449).

        ``method`` and ``uri`` are the HTTP request your handler actually
        served; the engine speaks no HTTP and cannot observe them.
        """
        return self.request(
            "oidc.dpop_verify",
            {
                "access_token": access_token,
                "dpop_proof": proof,
                "http_method": method,
                "http_uri": uri,
            },
        )

    def pushed_authorize(self, request: dict[str, Any]) -> Any:
        """Pushes an authorization request on the back channel (RFC 9126)."""
        return self.request("oidc.pushed_authorize", request)

    def device_authorize(self, client_id: str, scopes: list[str] | None = None) -> Any:
        return self.request(
            "oidc.device_authorize", {"client_id": client_id, "scopes": scopes or []}
        )

    def device_lookup(self, tenant_id: str, user_code: str) -> Any:
        return self.request(
            "oidc.device_lookup", {"tenant_id": tenant_id, "user_code": user_code}
        )

    def device_approve(
        self, tenant_id: str, user_code: str, session_id: str, session_secret: str
    ) -> Any:
        return self.request(
            "oidc.device_approve",
            {
                "tenant_id": tenant_id,
                "user_code": user_code,
                "session_id": session_id,
                "session_secret": session_secret,
            },
        )

    def device_deny(self, tenant_id: str, user_code: str) -> Any:
        return self.request(
            "oidc.device_deny", {"tenant_id": tenant_id, "user_code": user_code}
        )

    def token_exchange(self, request: dict[str, Any]) -> Any:
        return self.request("oidc.token", request)

    def refresh_family_revoke(self, family_id: str, reason: str = "") -> Any:
        return self.request("oidc.refresh_family_revoke", {"family_id": family_id, "reason": reason})

    def refresh_family_get(self, family_id: str) -> Any:
        return self.request("oidc.refresh_family_get", {"family_id": family_id})

    # ---- Consent ---------------------------------------------------------
    #
    # The session proves who is agreeing, so a caller cannot consent on
    # somebody else's behalf. Withdrawing also revokes that client's refresh
    # families for the principal.
    def consent_grant(
        self, session_id: str, session_secret: str, client_id: str, scopes: list[str]
    ) -> Any:
        return self.request(
            "oidc.consent_grant",
            {
                "session_id": session_id,
                "session_secret": session_secret,
                "client_id": client_id,
                "scopes": scopes,
            },
        )

    def consent_withdraw(self, principal_id: str, client_id: str) -> Any:
        return self.request(
            "oidc.consent_withdraw", {"principal_id": principal_id, "client_id": client_id}
        )

    def consent_get(self, principal_id: str, client_id: str) -> Any:
        return self.request(
            "oidc.consent_get", {"principal_id": principal_id, "client_id": client_id}
        )

    # ---- Standards surfaces ----------------------------------------------
    #
    # Endpoint paths are the host's own; the engine composes them under the
    # configured issuer and refuses any that would leave that origin.
    def standards_dispatch(self, request: dict[str, Any]) -> Any:
        parameters = {**request, "contract_version": "1"}
        return self.request("standards.dispatch", parameters)

    def discovery(self, endpoints: dict[str, str] | None = None) -> Any:
        return self.request("oidc.discovery", endpoints or {})

    def signing_keys(self) -> Any:
        return self.request("token.jwks", {})

    # Introspection reports live grant state, not just signature validity:
    # this is where a revoked session shows up.
    def introspect(self, client_id: str, client_secret: str, token: str) -> Any:
        return self.request(
            "oidc.introspect",
            {"token": token, "client_id": client_id, "client_secret": client_secret},
        )

    def revoke(self, client_id: str, client_secret: str, token: str) -> Any:
        return self.request(
            "oidc.revoke",
            {"token": token, "client_id": client_id, "client_secret": client_secret},
        )

    # The hint is required and may be expired; revoking its session also ends
    # every refresh grant resting on it.
    def logout(
        self, id_token_hint: str, post_logout_redirect_uri: str = "", state: str = ""
    ) -> Any:
        return self.request(
            "oidc.logout",
            {
                "id_token_hint": id_token_hint,
                "post_logout_redirect_uri": post_logout_redirect_uri,
                "state": state,
            },
        )

    # ---- Passkeys ---------------------------------------------------------
    #
    # Binary values cross the protocol as base64. A user-verified passkey
    # establishes MFA on its own, with no prior factor.
    def passkey_register_begin(self, principal_id: str) -> Any:
        return self.request(
            "authenticator.passkey_register_begin", {"principal_id": principal_id}
        )

    def passkey_register_finish(
        self, principal_id: str, attestation_object: bytes, client_data_json: bytes
    ) -> Any:
        return self.request(
            "authenticator.passkey_register_finish",
            {
                "principal_id": principal_id,
                "attestation_object": _base64url(attestation_object),
                "client_data_json": _base64url(client_data_json),
            },
        )

    def passkey_list(self, principal_id: str) -> Any:
        return self.request("authenticator.passkey_list", {"principal_id": principal_id})[
            "passkeys"
        ]

    def passkey_remove(self, credential_id: str) -> Any:
        return self.request("authenticator.passkey_remove", {"credential_id": credential_id})

    def passkey_options(self, transaction_id: str) -> Any:
        return self.request("authn.passkey_options", {"transaction_id": transaction_id})

    def authn_verify_passkey(
        self,
        transaction_id: str,
        credential_id: str,
        authenticator_data: bytes,
        client_data_json: bytes,
        signature: bytes,
    ) -> Any:
        return self.request(
            "authn.verify_passkey",
            {
                "transaction_id": transaction_id,
                "credential_id": credential_id,
                "authenticator_data": _base64url(authenticator_data),
                "client_data_json": _base64url(client_data_json),
                "signature": _base64url(signature),
            },
        )

    def close(self) -> None:
        """Ask the child to exit, forcing it after a bounded wait."""
        if self._closed:
            return
        self._closed = True
        if self._process.stdin is not None:
            self._process.stdin.close()
        try:
            self._process.wait(timeout=CLOSE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait()

    # Inbound OIDC federation. The engine performs no network I/O:
    # register and configure return the exact URL the host must fetch, and
    # every document the host brings back is validated in the engine as
    # untrusted input.
    # SCIM 2.0 provisioning. Every resource operation carries the bearer token, so the engine always authenticates and a host cannot forget to.
    def provisioning_client_register(
        self,
        tenant_id: str,
        name: str,
        identifier_namespace: str = "",
        can_manage_groups: bool = False,
    ) -> Any:
        return self.request(
            "scim.client_register",
            {
                "tenant_id": tenant_id,
                "name": name,
                "identifier_namespace": identifier_namespace,
                "can_manage_groups": can_manage_groups,
            },
        )

    def provisioning_client_disable(
        self, tenant_id: str, scim_client_id: str, reason: str = ""
    ) -> Any:
        return self.request(
            "scim.client_disable",
            {"tenant_id": tenant_id, "scim_client_id": scim_client_id, "reason": reason},
        )

    def provisioning_client_rotate_token(self, tenant_id: str, scim_client_id: str) -> Any:
        return self.request(
            "scim.client_rotate_token",
            {"tenant_id": tenant_id, "scim_client_id": scim_client_id},
        )

    # SCIM Group provisioning. These require the client's can_manage_groups
    # grant: group membership drives authorization decisions.
    def scim_group_create(self, token: str, body: str) -> Any:
        return self.request("scim.group_create", {"token": token, "body": body})

    def scim_group_get(self, token: str, resource_id: str) -> Any:
        return self.request("scim.group_get", {"token": token, "resource_id": resource_id})

    def scim_group_list(
        self, token: str, filter: str = "", start_index: int = 1, count: int = 0
    ) -> Any:
        return self.request(
            "scim.group_list",
            {"token": token, "filter": filter, "start_index": start_index, "count": count},
        )

    def scim_group_patch(self, token: str, resource_id: str, body: str) -> Any:
        return self.request(
            "scim.group_patch", {"token": token, "resource_id": resource_id, "body": body}
        )

    def scim_group_deprovision(self, token: str, resource_id: str) -> Any:
        return self.request(
            "scim.group_deprovision", {"token": token, "resource_id": resource_id}
        )

    def scim_user_create(self, token: str, body: str) -> Any:
        return self.request("scim.user_create", {"token": token, "body": body})

    def scim_user_get(self, token: str, resource_id: str) -> Any:
        return self.request("scim.user_get", {"token": token, "resource_id": resource_id})

    def scim_user_list(
        self, token: str, filter: str = "", start_index: int = 1, count: int = 0
    ) -> Any:
        return self.request(
            "scim.user_list",
            {"token": token, "filter": filter, "start_index": start_index, "count": count},
        )

    def scim_user_patch(self, token: str, resource_id: str, body: str) -> Any:
        return self.request(
            "scim.user_patch",
            {"token": token, "resource_id": resource_id, "body": body},
        )

    def scim_user_deprovision(self, token: str, resource_id: str) -> Any:
        return self.request(
            "scim.user_deprovision", {"token": token, "resource_id": resource_id}
        )

    def provider_register(
        self,
        tenant_id: str,
        name: str,
        issuer: str,
        client_id: str,
        client_secret: str,
        scopes: list[str],
        subject_claim: str = "sub",
        email_claim: str = "",
        linking: str = "strict",
    ) -> Any:
        return self.request(
            "federation.provider_register",
            {
                "tenant_id": tenant_id,
                "name": name,
                "issuer": issuer,
                "client_id": client_id,
                "client_secret": client_secret,
                "scopes": scopes,
                "subject_claim": subject_claim,
                "email_claim": email_claim,
                "linking": linking,
            },
        )

    def saml_provider_register(
        self,
        tenant_id: str,
        name: str,
        entity_id: str,
        sso_url: str,
        certificates: list[str],
        identifier_namespace: str = "email",
        linking: str = "strict",
    ) -> Any:
        return self.request(
            "saml.provider_register",
            {
                "tenant_id": tenant_id,
                "name": name,
                "entity_id": entity_id,
                "sso_url": sso_url,
                "certificates": certificates,
                "identifier_namespace": identifier_namespace,
                "linking": linking,
            },
        )

    def saml_provider_get(self, tenant_id: str, provider_id: str) -> Any:
        return self.request(
            "saml.provider_get", {"tenant_id": tenant_id, "provider_id": provider_id}
        )

    def saml_provider_disable(self, tenant_id: str, provider_id: str, reason: str = "") -> Any:
        return self.request(
            "saml.provider_disable",
            {"tenant_id": tenant_id, "provider_id": provider_id, "reason": reason},
        )

    def saml_login_start(self, tenant_id: str, provider_id: str, consumer_url: str) -> Any:
        return self.request(
            "saml.login_start",
            {"tenant_id": tenant_id, "provider_id": provider_id, "consumer_url": consumer_url},
        )

    def saml_login_complete(self, tenant_id: str, login_id: str, assertion: str) -> Any:
        return self.request(
            "saml.login_complete",
            {"tenant_id": tenant_id, "login_id": login_id, "assertion": assertion},
        )

    def provider_configure(
        self, tenant_id: str, provider_id: str, discovery_document: str, key_set_document: str
    ) -> Any:
        return self.request(
            "federation.provider_configure",
            {
                "tenant_id": tenant_id,
                "provider_id": provider_id,
                "discovery_document": discovery_document,
                "key_set_document": key_set_document,
            },
        )

    def provider_disable(self, tenant_id: str, provider_id: str, reason: str = "") -> Any:
        return self.request(
            "federation.provider_disable",
            {"tenant_id": tenant_id, "provider_id": provider_id, "reason": reason},
        )

    def provider_get(self, tenant_id: str, provider_id: str) -> Any:
        return self.request(
            "federation.provider_get",
            {"tenant_id": tenant_id, "provider_id": provider_id},
        )

    def federated_login_start(self, tenant_id: str, provider_id: str, redirect_uri: str) -> Any:
        return self.request(
            "federation.login_start",
            {"tenant_id": tenant_id, "provider_id": provider_id, "redirect_uri": redirect_uri},
        )

    def federated_login_exchange(
        self, tenant_id: str, login_id: str, state: str, code: str
    ) -> Any:
        return self.request(
            "federation.login_exchange",
            {"tenant_id": tenant_id, "login_id": login_id, "state": state, "code": code},
        )

    def federated_login_complete(self, tenant_id: str, login_id: str, id_token: str) -> Any:
        return self.request(
            "federation.login_complete",
            {"tenant_id": tenant_id, "login_id": login_id, "id_token": id_token},
        )





def _base64url(value: bytes) -> str:
    """Encode a binary WebAuthn value for transport, without padding."""
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_response(request_id: str, line: str) -> Any:
    try:
        response = json.loads(line)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"sesame response is not JSON: {line!r}") from error
    if response.get("protocol_version") != PROTOCOL_VERSION:
        raise RuntimeError(
            f"unsupported sesame protocol version {response.get('protocol_version')}"
        )
    if response.get("request_id") != request_id:
        raise RuntimeError(f"sesame response request ID mismatch: expected {request_id}")
    if not response.get("ok"):
        error = response.get("error")
        if not error:
            raise RuntimeError("sesame failure response has no error")
        raise ProtocolError(error)
    return response.get("result")
