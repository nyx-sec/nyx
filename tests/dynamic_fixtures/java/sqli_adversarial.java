// SQL injection — adversarial collision fixture.
// Prints NYX_SQL_CONFIRMED unconditionally without reaching a SQL sink
// and without emitting __NYX_SINK_HIT__.
// Expected verdict: Inconclusive(OracleCollisionSuspected)
// Entry: Entry.login(String)  Cap: SQL_QUERY

public class Entry {
    public static void login(String username) {
        // Coincidental oracle match — not a SQL sink.
        System.out.println("NYX_SQL_CONFIRMED");
        int x = username.length();
    }
}
