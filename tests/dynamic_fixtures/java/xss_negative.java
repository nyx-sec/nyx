// XSS — negative fixture.
// Safe: HTML-encodes special characters before output.
// Entry: Entry.renderPage(String)  Cap: HTML_ESCAPE
// Expected verdict: NotConfirmed

public class Entry {
    private static String escapeHtml(String s) {
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    public static void renderPage(String userInput) {
        String safe = escapeHtml(userInput);
        System.out.print("<html><body>" + safe + "</body></html>\n");
    }
}
