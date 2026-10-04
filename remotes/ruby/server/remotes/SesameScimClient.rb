#[HTTPClient({"path":"/api/v1/scim","adapter":"sesame","setup":"SesameSetup"})]
class SesameScimClient
  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/client-disable")]
  def client_disable(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/client-register")]
  def client_register(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/client-rotate-token")]
  def client_rotate_token(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param authorization [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/group-create")]
  def group_create(
    #[RequestHeader("Authorization")]
    authorization,
    #[RequestBody]
    body
  )
  end

  # @param authorization [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/group-deprovision")]
  def group_deprovision(
    #[RequestHeader("Authorization")]
    authorization,
    #[RequestBody]
    body
  )
  end

  # @param authorization [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/group-get")]
  def group_get(
    #[RequestHeader("Authorization")]
    authorization,
    #[RequestBody]
    body
  )
  end

  # @param authorization [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/group-list")]
  def group_list(
    #[RequestHeader("Authorization")]
    authorization,
    #[RequestBody]
    body
  )
  end

  # @param authorization [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/group-patch")]
  def group_patch(
    #[RequestHeader("Authorization")]
    authorization,
    #[RequestBody]
    body
  )
  end

  # @param authorization [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/user-create")]
  def user_create(
    #[RequestHeader("Authorization")]
    authorization,
    #[RequestBody]
    body
  )
  end

  # @param authorization [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/user-deprovision")]
  def user_deprovision(
    #[RequestHeader("Authorization")]
    authorization,
    #[RequestBody]
    body
  )
  end

  # @param authorization [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/user-get")]
  def user_get(
    #[RequestHeader("Authorization")]
    authorization,
    #[RequestBody]
    body
  )
  end

  # @param authorization [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/user-list")]
  def user_list(
    #[RequestHeader("Authorization")]
    authorization,
    #[RequestBody]
    body
  )
  end

  # @param authorization [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/user-patch")]
  def user_patch(
    #[RequestHeader("Authorization")]
    authorization,
    #[RequestBody]
    body
  )
  end
end
