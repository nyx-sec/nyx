import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;

@RestController
public class SpringHtmlReturnMethods {
    @GetMapping(value = "/a", produces = "text/html")
    public String a(@RequestParam String q) {
        return "<p>" + q.replace("a", "b") + "</p>";
    }

    @GetMapping(value = "/b", produces = "text/html")
    public String b(@RequestParam String q) {
        return "<p>" + q.substring(1) + "</p>";
    }

    @GetMapping(value = "/c", produces = "text/html")
    public String c(HttpServletRequest r) {
        return "<p>" + r.getParameter("q") + "</p>";
    }
}
