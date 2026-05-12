// Command injection — adversarial collision fixture.
// Prints NYX_PWN_CMDI unconditionally without reaching a command sink
// and without emitting __NYX_SINK_HIT__.
// Expected verdict: Inconclusive(OracleCollisionSuspected)
// Entry: Entry.runPing(String)  Cap: CODE_EXEC

public class Entry {
    public static void runPing(String host) {
        // Coincidental oracle match — not a shell sink.
        System.out.println("NYX_PWN_CMDI");
        int x = host.length();
    }
}
