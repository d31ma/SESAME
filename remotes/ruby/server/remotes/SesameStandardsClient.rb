#[HTTPClient({"path":"/oidc","adapter":"sesame","setup":"SesameSetup"})]
class SesameStandardsClient
  # @return [Hash]
  #[GetRequest("/jwks")]
  def jwks
  end

  # @return [Hash]
  #[GetRequest("/openid-configuration")]
  def openid_configuration
  end
end
