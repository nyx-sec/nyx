// Phase 20 (Track M.2) — RabbitMQ Java benign control.

import org.springframework.amqp.rabbit.annotation.RabbitListener;

public class Benign {
    public Benign() {}

    @RabbitListener(queues = "work")
    public void onMessage(String messageId, String body) throws Exception {
        new ProcessBuilder("echo", body).inheritIO().start().waitFor();
    }
}
