import javax.servlet.http.HttpServletRequest;
import org.springframework.web.client.RestTemplate;

public class SsrfRestTemplateUrl {
    public String fetch(HttpServletRequest request, RestTemplate rt) {
        String url = request.getParameter("url");
        return rt.getForObject(url, String.class);
    }

    public String fetchHost(HttpServletRequest request, RestTemplate rt) {
        String host = request.getParameter("host");
        return rt.getForObject("http://{host}/status", String.class, host);
    }
}
