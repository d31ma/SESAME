#[HTTPClient({"path":"/api/v1/principal","adapter":"sesame","setup":"SesameSetup"})]
class SesamePrincipalClient
  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/create")]
  def create(
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
  #[PostRequest("/suspend")]
  def suspend(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end
end
