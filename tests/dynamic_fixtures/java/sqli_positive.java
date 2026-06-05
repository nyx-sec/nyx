// SQL injection — positive fixture.
// Vulnerable: directly concatenates user input into SQL query string.
// Entry: Entry.login(String)  Cap: SQL_QUERY
// Expected verdict: Confirmed (UNION payload echoes NYX_SQL_CONFIRMED)

public class Entry {
    public static void login(String username) {
        String query = "SELECT name FROM users WHERE name='" + username + "'";
        System.out.print("__NYX_SINK_HIT__\n");
        // Error-based echo: output the query so UNION payload is visible.
        System.out.println("DB query: " + query);
    }
}
