import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import javax.servlet.http.*;
import java.security.Principal;

@RestController
public class SearchController {
    private JdbcTemplate jdbcTemplate;

    @GetMapping("/greet")
    public void greet(@RequestParam String name, HttpServletResponse resp) throws Exception {
        resp.getWriter().write(name);
    }

    @GetMapping("/pets")
    public Object pets(String owner) {
        return jdbcTemplate.queryForList("select * from pets where owner = '" + owner + "'");
    }

    @PostMapping("/find")
    public Object find(@RequestBody Query query, Principal principal) {
        return jdbcTemplate.queryForList("select * from t where n = '" + query.getName() + "'");
    }

    @GetMapping("/echo")
    public void echo(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String q = request.getParameter("q");
        response.getWriter().write(q);
    }

    static class Query {
        private String name;
        String getName() { return name; }
    }
}
