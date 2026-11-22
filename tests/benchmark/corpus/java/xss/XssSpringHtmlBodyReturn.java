import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class XssSpringHtmlBodyReturn {
    @GetMapping(value = "/hello/{name}", produces = "text/html")
    public String hello(@PathVariable("name") String name) {
        return "<h1>Hello " + name + "</h1>";
    }
}
