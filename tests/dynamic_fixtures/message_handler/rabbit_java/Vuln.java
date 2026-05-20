// Phase 20 (Track M.2) — RabbitMQ Java vuln fixture.
// `org.springframework.amqp.rabbit` consumer marker preserved;
// annotation elided so javac compiles without the Spring AMQP jar.

public class Vuln {
    public Vuln() {}

    public void onMessage(String messageId, String body) throws Exception {
        // SINK: tainted body concatenated into shell command
        new ProcessBuilder("sh", "-c", "echo " + body).inheritIO().start().waitFor();
    }
}
