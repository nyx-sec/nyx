// Phase 21 — Quartz benign control.
// org.quartz.Job marker (substring scan only).

public class Benign {
    public void execute(String payload) {
        System.out.println("scheduled: " + payload.replaceAll("[^A-Za-z0-9 _.-]", "_"));
    }
}
