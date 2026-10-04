@Setup
class SesameSetup {
    static Behaviors.Configuration configure(Behaviors.Execution execution) {
        return new Behaviors.Configuration(
            java.util.Map.of(),
            java.util.Map.of("sesame", new SesameTransportHelper()),
            java.util.Map.of(), null);
    }
}
