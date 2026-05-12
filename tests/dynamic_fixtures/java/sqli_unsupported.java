// SQL injection — unsupported fixture.
// Entry is an instance method rather than a static method.
// Test sets confidence = Low to get Unsupported(ConfidenceTooLow).
// Expected verdict: Unsupported

public class Entry {
    public void findUser(String name) {
        String query = "SELECT * FROM users WHERE name='" + name + "'";
        System.out.println(query);
    }
}
