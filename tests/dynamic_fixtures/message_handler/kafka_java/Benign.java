// Phase 20 (Track M.2) — Kafka Java benign control.

import org.springframework.kafka.annotation.KafkaListener;

public class Benign {
    public Benign() {}

    @KafkaListener(topics = "orders")
    public void onMessage(String body) throws Exception {
        new ProcessBuilder("echo", body).inheritIO().start().waitFor();
    }
}
