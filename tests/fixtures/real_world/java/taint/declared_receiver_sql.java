import java.util.List;
import java.util.Map;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.support.JdbcDaoSupport;

public class DeclaredReceiverSql extends JdbcDaoSupport {
    private JdbcTemplate template;
    private NamedParameterJdbcTemplate namedTemplate;
    private EntityManager manager;

    public List<Map<String, Object>> byField(HttpServletRequest req) {
        String name = req.getParameter("name");
        return template.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
    }

    public List<Map<String, Object>> byNamedTemplate(HttpServletRequest req) {
        String name = req.getParameter("name");
        return namedTemplate.queryForList("SELECT * FROM users WHERE name = '" + name + "'", Map.of());
    }

    public Map<String, Object> byAccessor(HttpServletRequest req) {
        String name = req.getParameter("name");
        return getJdbcTemplate().queryForMap("SELECT * FROM users WHERE name = '" + name + "'");
    }

    public void batch(HttpServletRequest req) {
        String name = req.getParameter("name");
        template.batchUpdate("DELETE FROM users WHERE name = '" + name + "'");
    }

    public List<?> entityManager(HttpServletRequest req) {
        String name = req.getParameter("name");
        return manager.createQuery("FROM User WHERE name = '" + name + "'").getResultList();
    }

    public List<Map<String, Object>> safePlaceholder(HttpServletRequest req) {
        String name = req.getParameter("name");
        return template.queryForList("SELECT * FROM users WHERE name = ?", name);
    }

    public List<Map<String, Object>> safeNamed(HttpServletRequest req) {
        String name = req.getParameter("name");
        return namedTemplate.queryForList("SELECT * FROM users WHERE name = :name", Map.of("name", name));
    }

    public Map<String, Object> safeAccessor(HttpServletRequest req) {
        String name = req.getParameter("name");
        return getJdbcTemplate().queryForMap("SELECT * FROM users WHERE name = ?", name);
    }

    public List<?> safeEntityManager(HttpServletRequest req) {
        String name = req.getParameter("name");
        return manager.createQuery("FROM User WHERE name = :name").setParameter("name", name).getResultList();
    }
}
