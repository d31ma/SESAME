#[HTTPClient({"path":"/oidc","adapter":"sesame","setup":"SesameSetup"})]
trait SesameStandardsClient {
    #[GetRequest("/jwks")]
    fn jwks(&self) -> BehaviorResult<BehaviorValue>;

    #[GetRequest("/openid-configuration")]
    fn openid_configuration(&self) -> BehaviorResult<BehaviorValue>;
}
