// SQL injection — negative fixture.
// Safe: uses a parameterized query; payload is a bound argument.
// Entry: Entry.login(String)  Cap: SQL_QUERY
// Expected verdict: NotConfirmed

public class Entry {
    public static void login(String username) {
        String template = "SELECT name FROM users WHERE name = ?";
        // Simulate parameterized execution: template is fixed.
        System.out.println("Executing: " + template + " param-len=" + username.length());
    }
}
