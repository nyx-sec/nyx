// Phase 20 (Track M.2) — Kafka Java benign control.
// `org.springframework.kafka` adapter marker preserved.
public class Benign {
    public Benign() {}

    public void onMessage(String body) throws Exception {
        new ProcessBuilder("echo", body).inheritIO().start().waitFor();
    }
}
