@Setup
class SesameSetup {
  static BehaviorAdapters configure(BehaviorExecution execution) {
    return BehaviorAdapters(http: {'sesame': BehaviorHttpAdapter(exchange: SesameTransportHelper().exchange)});
  }
}
