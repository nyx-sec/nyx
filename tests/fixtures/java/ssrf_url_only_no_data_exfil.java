// Regression fixture: a tainted URL flowing into HttpClient.send must
// fire SSRF (taint-unsanitised-flow) but must NOT fire DATA_EXFIL.
// The body is a hardcoded literal so no Sensitive payload reaches the
// outbound request.  This guards against over-firing DATA_EXFIL on
// flows where only the URL position is attacker-controlled.
//
// Driven by `data_exfil_java_integration_tests.rs`.
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import javax.servlet.http.HttpServletRequest;

public class SsrfUrlOnlyNoDataExfil {
    public void doGet(HttpServletRequest request) throws Exception {
        String target = request.getParameter("url");
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(target))
            .POST(BodyPublishers.ofString("ping"))
            .build();
        client.send(req, BodyHandlers.ofString());
    }
}
