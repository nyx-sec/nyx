// Phase 08 (Track J.6) — Java HEADER_INJECTION benign control fixture.
//
// Same shape as `Vuln.java` but URL-encodes the value via
// `URLEncoder.encode` (the OWASP-recommended defence), so any CRLF
// bytes in the value land as `%0D%0A` and the wire keeps a single
// header.
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletResponse;

public class Benign {
    public static void run(HttpServletResponse response, String value) {
        String encoded = URLEncoder.encode(value, StandardCharsets.UTF_8);
        response.setHeader("Set-Cookie", encoded);
    }
}
