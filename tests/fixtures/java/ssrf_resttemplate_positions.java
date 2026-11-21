// RestTemplate argument positions.  Only the URL (arg 0) can move the
// request to another host.  The request body and the trailing uriVariables
// are expanded into the body and the path of the fixed template, so a
// request parameter there is not SSRF.  A variable in the scheme or
// authority of the template does let the uriVariables choose the host.
//
// Driven by `data_exfil_java_integration_tests.rs`, which pins each case by
// the method it lives in (the safe_* methods first, the unsafe_* after).
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.client.RestTemplate;

public class SsrfRestTemplatePositions {
    public void safe_body(HttpServletRequest req, RestTemplate rt) {
        String body = req.getParameter("b");
        rt.postForObject("https://api.example.com/notify", body, String.class);
    }

    public void safe_entity(HttpServletRequest req, RestTemplate rt) {
        String body = req.getParameter("b");
        rt.postForEntity("https://api.example.com/notify", body, String.class);
    }

    public String safe_path_variable(HttpServletRequest req, RestTemplate rt) {
        String id = req.getParameter("id");
        return rt.getForObject("https://api.example.com/users/{id}", String.class, id);
    }

    public String safe_wrapper_call(HttpServletRequest req, RestTemplate rt) {
        return fetchUser(rt, req.getParameter("id"));
    }

    private String fetchUser(RestTemplate rt, String id) {
        return rt.getForObject("https://api.example.com/users/{id}", String.class, id);
    }

    public String unsafe_url(HttpServletRequest req, RestTemplate rt) {
        String url = req.getParameter("url");
        return rt.getForObject(url, String.class);
    }

    public String unsafe_post_url(HttpServletRequest req, RestTemplate rt) {
        String url = req.getParameter("url");
        return rt.postForObject(url, "x", String.class);
    }

    public String unsafe_host_template(HttpServletRequest req, RestTemplate rt) {
        String host = req.getParameter("host");
        return rt.getForObject("http://{host}/api", String.class, host);
    }
}
