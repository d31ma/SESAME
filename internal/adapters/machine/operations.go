package machine

// Operations is every operation this binary routes, in sorted order.
//
// It exists so a client can ask what the engine actually supports instead of
// discovering a missing operation partway through a security flow. The list is
// asserted against the dispatch switch and against
// `api/machine/v1/operations.json` by test/contract, so it cannot drift from
// either the code or the published manifest.
var Operations = []string{
	"admin.bootstrap",
	"authenticator.passkey_list",
	"authenticator.passkey_register_begin",
	"authenticator.passkey_register_finish",
	"authenticator.passkey_remove",
	"authenticator.recovery_codes_issue",
	"authenticator.set_password",
	"authenticator.totp_activate",
	"authenticator.totp_enroll",
	"authn.begin",
	"authn.complete",
	"authn.passkey_options",
	"authn.verify_passkey",
	"authn.verify_password",
	"authn.verify_recovery_code",
	"authn.verify_totp",
	"authorize.decide",
	"authorize.decide_batch",
	"federation.login_complete",
	"federation.login_exchange",
	"federation.login_start",
	"federation.provider_configure",
	"federation.provider_disable",
	"federation.provider_get",
	"federation.provider_register",
	"grant.create",
	"grant.revoke",
	"group.create",
	"group.member_add",
	"group.member_remove",
	"oidc.authorize",
	"oidc.consent_get",
	"oidc.consent_grant",
	"oidc.consent_withdraw",
	"oidc.device_approve",
	"oidc.device_authorize",
	"oidc.device_deny",
	"oidc.device_lookup",
	"oidc.discovery",
	"oidc.dpop_verify",
	"oidc.interaction_complete",
	"oidc.interaction_get",
	"oidc.introspect",
	"oidc.logout",
	"oidc.pushed_authorize",
	"oidc.refresh_family_get",
	"oidc.refresh_family_revoke",
	"oidc.revoke",
	"oidc.token",
	"oidc_client.disable",
	"oidc_client.get",
	"oidc_client.register",
	"oidc_client.rotate_secret",
	"principal.create",
	"principal.get",
	"principal.suspend",
	"role.create",
	"saml.login_complete",
	"saml.login_start",
	"saml.provider_disable",
	"saml.provider_get",
	"saml.provider_register",
	"scim.client_disable",
	"scim.client_register",
	"scim.client_rotate_token",
	"scim.group_create",
	"scim.group_deprovision",
	"scim.group_get",
	"scim.group_list",
	"scim.group_patch",
	"scim.user_create",
	"scim.user_deprovision",
	"scim.user_get",
	"scim.user_list",
	"scim.user_patch",
	"session.revoke",
	"session.verify",
	"standards.dispatch",
	"system.metrics",
	"system.ping",
	"system.readiness",
	"system.version",
	"tenant.bootstrap",
	"tenant.get",
	"token.jwks",
}

// VersionReport is the system.version result: immutable build metadata plus
// what this binary can be asked to do.
//
// Protocol version and operations travel together with the build identity so
// one call answers "may I talk to you, and can you do what I need" — the two
// questions a client has before it starts a flow it cannot finish.
type VersionReport struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	Commit          string   `json:"commit"`
	BuiltAt         string   `json:"built_at"`
	GoVersion       string   `json:"go_version"`
	OS              string   `json:"os"`
	Arch            string   `json:"arch"`
	ProtocolVersion string   `json:"protocol_version"`
	Operations      []string `json:"operations"`
}
