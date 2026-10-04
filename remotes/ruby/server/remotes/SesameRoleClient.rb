#[HTTPClient({"path":"/api/v1/role","adapter":"sesame","setup":"SesameSetup"})]
class SesameRoleClient
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
end
