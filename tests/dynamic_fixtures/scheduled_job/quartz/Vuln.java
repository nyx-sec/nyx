// Phase 21 (Track M.3) — Quartz scheduled-job vuln fixture.
//
// `Vuln` implements the Quartz `Job` interface (substring-marker only
// — the real `org.quartz.Job` symbol is not on the JDK classpath).
// `execute(JobExecutionContext)` splices the payload into a shell
// command via `Runtime.exec`, the classic Quartz job cmdi shape.

// org.quartz.Job marker (substring scan only — not a real import).
// @DisallowConcurrentExecution

public class Vuln {
    public void execute(String payload) throws Exception {
        // SINK: tainted payload concatenated into shell command.
        Runtime.getRuntime().exec(new String[] { "/bin/sh", "-c", "echo " + payload });
    }
}
