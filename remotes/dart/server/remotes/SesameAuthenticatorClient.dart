@HTTPClient({"path":"/api/v1/authenticator","adapter":"sesame","setup":"SesameSetup"})
abstract interface class SesameAuthenticatorClient {
  @PostRequest("/passkey-list")
  Future<Object?> passkeyList(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/passkey-list-for-principal")
  Future<Object?> passkeyListForPrincipal(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/passkey-register-begin")
  Future<Object?> passkeyRegisterBegin(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/passkey-register-finish")
  Future<Object?> passkeyRegisterFinish(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/passkey-remove")
  Future<Object?> passkeyRemove(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/passkey-remove-for-principal")
  Future<Object?> passkeyRemoveForPrincipal(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/recovery-codes-issue")
  Future<Object?> recoveryCodesIssue(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/set-password")
  Future<Object?> setPassword(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/set-password-for-principal")
  Future<Object?> setPasswordForPrincipal(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/totp-activate")
  Future<Object?> totpActivate(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/totp-enroll")
  Future<Object?> totpEnroll(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);
}
