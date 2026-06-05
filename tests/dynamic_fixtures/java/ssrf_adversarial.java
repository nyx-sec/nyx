// SSRF — adversarial collision fixture.
// Prints "daemon:" unconditionally without making any HTTP request
// and without emitting __NYX_SINK_HIT__.
// Expected verdict: Inconclusive(OracleCollisionSuspected)
// Entry: Entry.fetchUrl(String)  Cap: SSRF

public class Entry {
    public static void fetchUrl(String targetUrl) {
        // Coincidental oracle match — not an HTTP sink.
        System.out.println("daemon: present");
        int x = targetUrl.length();
    }
}
