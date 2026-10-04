@Setup
class SesameSetup {
    companion object {
        fun configure(execution: Behaviors.Execution): Behaviors.Configuration =
            Behaviors.Configuration(http = mapOf("sesame" to SesameTransportHelper()))
    }
}
