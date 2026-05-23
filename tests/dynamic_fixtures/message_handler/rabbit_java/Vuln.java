// Phase 20 (Track M.2) — RabbitMQ Java vuln fixture.

import org.springframework.amqp.rabbit.annotation.RabbitListener;

public class Vuln {
    public Vuln() {}

    @RabbitListener(queues = "work")
    public void onMessage(String messageId, String body) throws Exception {
        // SINK: tainted body concatenated into shell command
        new ProcessBuilder("sh", "-c", "echo " + body).inheritIO().start().waitFor();
    }
}
