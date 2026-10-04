#[HTTPClient({"path":"/api/v1/authorize","adapter":"sesame","setup":"SesameSetup"})]
class SesameAuthorizeClient
  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/decide")]
  def decide(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/decide-batch")]
  def decide_batch(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end
end
