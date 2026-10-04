#[HTTPClient({"path":"/api/v1/oidc-client","adapter":"sesame","setup":"SesameSetup"})]
class SesameOidcClientClient
  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/disable")]
  def disable(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/get")]
  def get(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/register")]
  def register(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/rotate-secret")]
  def rotate_secret(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end
end
