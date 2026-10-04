#[yon::setup]
struct SesameSetup {}
impl SesameSetup {
    fn configure(_execution: &BehaviorExecution) -> BehaviorResult<BehaviorConfiguration> {
        let mut configuration = BehaviorConfiguration::default();
        configuration.http.insert("sesame".into(), std::sync::Arc::new(SesameTransportHelper));
        Ok(configuration)
    }
}
