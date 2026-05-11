// Phase 14 fixture (Java positive) — attacker-controlled URL passed to
// `HttpClient.send`. The `HttpClient.newHttpClient()` factory call tags
// the local `client` SSA value as `TypeKind::HttpClient`, so the
// `client.send` callee resolves through the type-qualified rewrite to
// `HttpClient.send` against the existing flat SSRF rule.
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import javax.servlet.http.HttpServletRequest;

public class SsrfJavaPositive {
    public String proxy(HttpServletRequest req) throws Exception {
        String target = req.getParameter("url");
        URI uri = URI.create(target);
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest httpReq = HttpRequest.newBuilder().uri(uri).build();
        HttpResponse<String> resp = client.send(httpReq, HttpResponse.BodyHandlers.ofString());
        return resp.body();
    }
}
