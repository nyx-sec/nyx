import static org.apache.commons.text.StringEscapeUtils.escapeHtml4;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SpringHtmlBodyReturnSafe {
    // Escaped before it is returned as HTML.
    @GetMapping(value = "/hello/{name}", produces = "text/html")
    public String hello(@PathVariable("name") String name) {
        return "<h1>Hello " + escapeHtml4(name) + "</h1>";
    }

    // No HTML content type: a JSON or plain text body is not an XSS sink.
    @GetMapping("/echo/{name}")
    public String echo(@PathVariable("name") String name) {
        return "Hello " + name;
    }

    // A built string whose appended value is escaped.
    @GetMapping(value = "/page", produces = "text/html")
    public String page(@RequestParam("title") String title) {
        StringBuilder sb = new StringBuilder("<html><title>");
        sb.append(escapeHtml4(title));
        sb.append("</title></html>");
        return sb.toString();
    }
}

@Controller
class SpringViewController {
    // A Controller without @ResponseBody returns a view name, not a body.
    @GetMapping(value = "/view/{name}", produces = "text/html")
    public String view(@PathVariable("name") String name) {
        return "views/" + name;
    }
}
