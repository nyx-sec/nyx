// Phase 20 (Track M.2) — SQS Java vuln fixture.

import io.awspring.cloud.sqs.annotation.SqsListener;

public class Vuln {
    public Vuln() {}

    @SqsListener("jobs")
    public void handleMessage(java.util.Map<String, String> env) throws Exception {
        String body = env != null ? env.getOrDefault("Body", "") : "";
        // SINK: tainted Body concatenated into shell command
        new ProcessBuilder("sh", "-c", "echo " + body).inheritIO().start().waitFor();
    }
}
