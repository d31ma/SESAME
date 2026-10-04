#[HTTPClient({"path":"/api/v1/oidc","adapter":"sesame","setup":"SesameSetup"})]
class SesameOidcClient
  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/consent-get")]
  def consent_get(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/consent-grant")]
  def consent_grant(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/consent-withdraw")]
  def consent_withdraw(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/device-approve")]
  def device_approve(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/device-authorize")]
  def device_authorize(
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/device-deny")]
  def device_deny(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/device-lookup")]
  def device_lookup(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/dpop-verify")]
  def dpop_verify(
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/interaction-complete")]
  def interaction_complete(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/interaction-get")]
  def interaction_get(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/pushed-authorize")]
  def pushed_authorize(
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/refresh-family-get")]
  def refresh_family_get(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end

  # @param session [String]
  # @param body [Hash]
  # @return [Hash]
  #[PostRequest("/refresh-family-revoke")]
  def refresh_family_revoke(
    #[RequestHeader("Sesame-Session")]
    session,
    #[RequestBody]
    body
  )
  end
end
