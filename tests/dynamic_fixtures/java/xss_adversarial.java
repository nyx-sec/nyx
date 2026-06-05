// XSS — adversarial collision fixture.
// Prints the XSS oracle marker unconditionally without rendering any template
// and without emitting __NYX_SINK_HIT__.
// Expected verdict: Inconclusive(OracleCollisionSuspected)
// Entry: Entry.renderPage(String)  Cap: HTML_ESCAPE

public class Entry {
    public static void renderPage(String userInput) {
        // Coincidental oracle match — not an HTML render sink.
        System.out.println("<script>NYX_XSS_CONFIRMED</script>");
        int x = userInput.length();
    }
}
