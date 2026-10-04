#[HTTPClient({"path":"/api/v1/session","adapter":"sesame","setup":"SesameSetup"})]
class SesameSessionClient
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

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/revoke-by-id")]
  def revoke_by_id(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/verify")]
  def verify(
    #[RequestBody]
    body
  )
  end
end
