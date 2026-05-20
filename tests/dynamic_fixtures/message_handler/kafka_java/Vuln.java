// Phase 20 (Track M.2) — Kafka Java vuln fixture.
//
// Marker line so the kafka-java framework adapter binds:
// `org.springframework.kafka` consumer entry point.  Annotation is
// elided so javac compiles without the Spring jar; the dynamic harness
// invokes onMessage reflectively.

public class Vuln {
    public Vuln() {}

    public void onMessage(String body) throws Exception {
        // SINK: tainted body concatenated into shell command
        new ProcessBuilder("sh", "-c", "echo " + body).inheritIO().start().waitFor();
    }
}
