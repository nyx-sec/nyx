import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SpringHtmlBodyReturn {
    // The returned String is the text/html response body.
    @GetMapping(value = "/hello/{name}", produces = "text/html")
    public String hello(@PathVariable("name") String name) {
        return "<h1>Hello " + name + "</h1>";
    }

    @RequestMapping(value = "/page", produces = {"text/html", "text/html;charset=UTF-8"})
    public String page(@RequestParam("title") String title) {
        StringBuilder sb = new StringBuilder("<html><head><title>");
        sb.append(title);
        sb.append("</title></head></html>");
        return sb.toString();
    }
}
