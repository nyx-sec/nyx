// Phase 20 (Track M.2) — SQS Java vuln fixture.
// `io.awspring.cloud.sqs` consumer entry point — annotation elided so
// javac compiles without the Spring Cloud AWS jar.

public class Vuln {
    public Vuln() {}

    public void handleMessage(java.util.Map<String, String> env) throws Exception {
        String body = env != null ? env.getOrDefault("Body", "") : "";
        // SINK: tainted Body concatenated into shell command
        new ProcessBuilder("sh", "-c", "echo " + body).inheritIO().start().waitFor();
    }
}
