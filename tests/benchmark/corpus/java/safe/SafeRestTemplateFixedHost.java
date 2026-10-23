import javax.servlet.http.HttpServletRequest;
import org.springframework.web.client.RestTemplate;

public class SafeRestTemplateFixedHost {
    public String notify(HttpServletRequest request, RestTemplate rt) {
        String body = request.getParameter("message");
        return rt.postForObject("https://api.example.com/notify", body, String.class);
    }

    public String user(HttpServletRequest request, RestTemplate rt) {
        String id = request.getParameter("id");
        return rt.getForObject("https://api.example.com/users/{id}", String.class, id);
    }
}
