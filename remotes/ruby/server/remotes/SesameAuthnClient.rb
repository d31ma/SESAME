#[HTTPClient({"path":"/api/v1/authn","adapter":"sesame","setup":"SesameSetup"})]
class SesameAuthnClient
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/begin")]
  def begin(
    #[RequestBody]
    body
  )
  end

  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/complete")]
  def complete(
    #[RequestBody]
    body
  )
  end

  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/passkey-options")]
  def passkey_options(
    #[RequestBody]
    body
  )
  end

  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/verify-passkey")]
  def verify_passkey(
    #[RequestBody]
    body
  )
  end

  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/verify-password")]
  def verify_password(
    #[RequestBody]
    body
  )
  end

  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/verify-recovery-code")]
  def verify_recovery_code(
    #[RequestBody]
    body
  )
  end

  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/verify-totp")]
  def verify_totp(
    #[RequestBody]
    body
  )
  end
end
