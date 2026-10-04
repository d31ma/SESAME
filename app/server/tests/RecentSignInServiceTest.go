// @Test(SesameTestSetup, {"partition":"tests"})
type RecentSignInServiceTest struct {
	behaviors *BehaviorContext
}

func (test *RecentSignInServiceTest) TestCredentialAndPrivilegeChangesArePrivileged() {
	service := &RecentSignInService{}
	privileged := []bool{}
	for _, operation := range test.changes() {
		privileged = append(privileged, service.Privileged(EngineCall{Operation: operation}))
	}

	Assert.Equals(test.everyOne(len(test.changes())), privileged)
}

func (test *RecentSignInServiceTest) TestReadsAndReductionsAreNotPrivileged() {
	service := &RecentSignInService{}
	privileged := []bool{}
	for _, operation := range test.readsAndReductions() {
		privileged = append(privileged, service.Privileged(EngineCall{Operation: operation}))
	}

	Assert.Equals(make([]bool, len(test.readsAndReductions())), privileged)
}

func (test *RecentSignInServiceTest) TestAMarkedCallIsPrivileged() {
	service := &RecentSignInService{}

	Assert.IsTrue(service.Privileged(EngineCall{Operation: "authenticator.passkey_list", Privileged: true}))
}

func (test *RecentSignInServiceTest) changes() []string {
	return []string{
		"authenticator.set_password", "authenticator.totp_enroll", "authenticator.totp_activate",
		"authenticator.recovery_codes_issue", "authenticator.passkey_register_begin",
		"authenticator.passkey_register_finish", "authenticator.passkey_remove",
		"federation.provider_register", "federation.provider_configure", "grant.create", "group.member_add",
		"oidc_client.register", "oidc_client.rotate_secret", "principal.suspend", "saml.provider_register",
		"scim.client_register", "scim.client_rotate_token",
	}
}

func (test *RecentSignInServiceTest) readsAndReductions() []string {
	return []string{
		"authenticator.passkey_list", "principal.get", "principal.create", "role.create", "group.create",
		"group.member_remove", "grant.revoke", "session.revoke", "oidc_client.get", "oidc_client.disable",
		"oidc.refresh_family_revoke", "federation.provider_disable", "saml.provider_disable",
		"scim.client_disable", "authorize.decide", "tenant.get", "system.metrics",
	}
}

func (test *RecentSignInServiceTest) everyOne(count int) []bool {
	all := make([]bool, count)
	for index := range all {
		all[index] = true
	}
	return all
}
