@Setup
export default class SesameSetup {
  static configure(execution: BehaviorExecution): BehaviorConfiguration {
    return { http: { sesame: new SesameTransportHelper() } };
  }
}
