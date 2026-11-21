import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

public class SqliJdbcTemplateDeclared {
    private JdbcTemplate template;
    private NamedParameterJdbcTemplate named;

    public List<Map<String, Object>> byName(HttpServletRequest request) {
        String name = request.getParameter("name");
        return template.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
    }

    public List<Map<String, Object>> byNamedTemplate(HttpServletRequest request) {
        String name = request.getParameter("name");
        return named.queryForList("SELECT * FROM users WHERE name = '" + name + "'", Map.of());
    }
}
