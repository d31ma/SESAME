@HTTPClient({"path":"/api/v1/authn","adapter":"sesame","setup":"SesameSetup"})
abstract interface class SesameAuthnClient {
  @PostRequest("/begin")
  Future<Object?> begin(@RequestBody Object? body);

  @PostRequest("/complete")
  Future<Object?> complete(@RequestBody Object? body);

  @PostRequest("/passkey-options")
  Future<Object?> passkeyOptions(@RequestBody Object? body);

  @PostRequest("/verify-passkey")
  Future<Object?> verifyPasskey(@RequestBody Object? body);

  @PostRequest("/verify-password")
  Future<Object?> verifyPassword(@RequestBody Object? body);

  @PostRequest("/verify-recovery-code")
  Future<Object?> verifyRecoveryCode(@RequestBody Object? body);

  @PostRequest("/verify-totp")
  Future<Object?> verifyTotp(@RequestBody Object? body);
}
