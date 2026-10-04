#[HTTPClient({"path":"/api/v1/group","adapter":"sesame","setup":"SesameSetup"})]
class SesameGroupClient
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
  #[PostRequest("/member-add")]
  def member_add(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/member-remove")]
  def member_remove(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end
end
