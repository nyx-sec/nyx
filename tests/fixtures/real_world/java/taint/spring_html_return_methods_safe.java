import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.util.HtmlUtils;

@RestController
public class SpringHtmlReturnMethodsSafe {
    @GetMapping(value = "/a", produces = "text/html")
    public String a(@RequestParam String q) {
        return "<p>" + HtmlUtils.htmlEscape(q.replace("a", "b")) + "</p>";
    }

    @GetMapping(value = "/c", produces = "text/html")
    public String c(HttpServletRequest r) {
        return "<p>" + HtmlUtils.htmlEscape(r.getParameter("q")) + "</p>";
    }

    @GetMapping(value = "/d", produces = "text/html")
    public String d(@RequestParam String q) {
        return "<p>" + "fixed".substring(1) + "</p>";
    }

    // No HTML content type: a plain text body is not an XSS sink.
    @GetMapping("/e")
    public String e(@RequestParam String q) {
        return "<p>" + q.substring(1) + "</p>";
    }
}
