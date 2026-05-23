// Phase 20 (Track M.2) — Kafka Java vuln fixture.

import org.springframework.kafka.annotation.KafkaListener;

public class Vuln {
    public Vuln() {}

    @KafkaListener(topics = "orders")
    public void onMessage(String body) throws Exception {
        // SINK: tainted body concatenated into shell command
        new ProcessBuilder("sh", "-c", "echo " + body).inheritIO().start().waitFor();
    }
}
