// Phase 14 fixture (Java negative) — `"https://api.example.com/" + path`
// produces a StringFact whose prefix is the literal scheme/host. The
// `RestTemplate.getForObject(url, ...)` SSRF sink reads the URL at
// arg 0; `is_abstract_safe_for_sink` honours the prefix-lock and
// suppresses the finding even though the path component is
// attacker-controlled.
import org.springframework.web.client.RestTemplate;
import javax.servlet.http.HttpServletRequest;

public class SsrfJavaOriginLocked {
    public void proxy(HttpServletRequest req) {
        String path = req.getParameter("path");
        String url = "https://api.example.com/" + path;
        RestTemplate rt = new RestTemplate();
        String body = rt.getForObject(url, String.class);
    }
}
