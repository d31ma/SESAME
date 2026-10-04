#[HTTPClient({"path":"/api/v1/token","adapter":"sesame","setup":"SesameSetup"})]
class SesameTokenClient
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/jwks")]
  def jwks(
    #[RequestBody]
    body
  )
  end
end
