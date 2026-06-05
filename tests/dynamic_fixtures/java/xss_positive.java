// XSS — positive fixture.
// Vulnerable: echoes raw user input into HTML output without escaping.
// Entry: Entry.renderPage(String)  Cap: HTML_ESCAPE
// Expected verdict: Confirmed (<script>NYX_XSS_CONFIRMED</script> echoed)

public class Entry {
    public static void renderPage(String userInput) {
        System.out.print("__NYX_SINK_HIT__\n");
        System.out.print("<html><body>" + userInput + "</body></html>\n");
    }
}
