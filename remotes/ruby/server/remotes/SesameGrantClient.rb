#[HTTPClient({"path":"/api/v1/grant","adapter":"sesame","setup":"SesameSetup"})]
class SesameGrantClient
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
  #[PostRequest("/revoke")]
  def revoke(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end
end
