// Phase 20 (Track M.2) — SQS Java benign control.

import io.awspring.cloud.sqs.annotation.SqsListener;

public class Benign {
    public Benign() {}

    @SqsListener("jobs")
    public void handleMessage(java.util.Map<String, String> env) throws Exception {
        String body = env != null ? env.getOrDefault("Body", "") : "";
        new ProcessBuilder("echo", body).inheritIO().start().waitFor();
    }
}
