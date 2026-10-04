#[HTTPClient({"path":"/api/v1/tenant","adapter":"sesame","setup":"SesameSetup"})]
class SesameTenantClient
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
end
