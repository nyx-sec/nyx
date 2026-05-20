// Phase 20 (Track M.2) — RabbitMQ Java benign control.
// `org.springframework.amqp.rabbit` adapter marker preserved.

public class Benign {
    public Benign() {}

    public void onMessage(String messageId, String body) throws Exception {
        new ProcessBuilder("echo", body).inheritIO().start().waitFor();
    }
}
