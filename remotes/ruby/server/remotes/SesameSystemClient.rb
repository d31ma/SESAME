#[HTTPClient({"path":"/api/v1/system","adapter":"sesame","setup":"SesameSetup"})]
class SesameSystemClient
  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/build")]
  def build(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/metrics")]
  def metrics(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/ping")]
  def ping(
    #[RequestBody]
    body
  )
  end

  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/readiness")]
  def readiness(
    #[RequestBody]
    body
  )
  end

  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/version")]
  def version(
    #[RequestBody]
    body
  )
  end
end
