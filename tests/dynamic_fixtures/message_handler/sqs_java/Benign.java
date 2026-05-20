// Phase 20 (Track M.2) — SQS Java benign control.
// `io.awspring.cloud.sqs` adapter marker preserved.

public class Benign {
    public Benign() {}

    public void handleMessage(java.util.Map<String, String> env) throws Exception {
        String body = env != null ? env.getOrDefault("Body", "") : "";
        new ProcessBuilder("echo", body).inheritIO().start().waitFor();
    }
}
