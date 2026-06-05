// XSS — unsupported fixture.
// Entry is an instance method; test sets confidence = Low.
// Expected verdict: Unsupported

public class Entry {
    public void render(String input) {
        System.out.print("<html><body>" + input + "</body></html>\n");
    }
}
