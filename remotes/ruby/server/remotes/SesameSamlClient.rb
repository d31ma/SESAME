#[HTTPClient({"path":"/api/v1/saml","adapter":"sesame","setup":"SesameSetup"})]
class SesameSamlClient
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/login-complete")]
  def login_complete(
    #[RequestBody]
    body
  )
  end

  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/login-start")]
  def login_start(
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/provider-disable")]
  def provider_disable(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/provider-get")]
  def provider_get(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/provider-register")]
  def provider_register(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end
end
