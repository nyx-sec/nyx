import java.sql.*;
import java.security.SecureRandom;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.apache.commons.text.StringSubstitutor;

class Negative {
    // Safe: parameterized query
    void safeQuery(Connection conn, String user) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, user);
        ResultSet rs = ps.executeQuery();
    }

    // Safe: SecureRandom instead of Random
    void safeRandom() {
        SecureRandom sr = new SecureRandom();
        int token = sr.nextInt();
    }

    // Safe: no concatenation in SQL
    void safeLiteralQuery(Statement stmt) throws Exception {
        stmt.executeQuery("SELECT COUNT(*) FROM users");
    }

    // Safe: SnakeYAML 2.0 / explicit SafeConstructor — CVE-2022-1471 fix shape.
    void safeSnakeyamlSafeConstructor(String body) {
        LoaderOptions opts = new LoaderOptions();
        Yaml yaml = new Yaml(new SafeConstructor(opts));
        Object data = yaml.load(body);
    }

    // Safe: an `invoke` of the class's own, never java.lang.reflect.Method.invoke:
    // unqualified, via `this` / `super`, with no argument, or on a new object.
    // (Receiver types and lambda arguments are judged after the query, see the
    // unit tests in src/ast.rs.)
    Object own(String realm) { return invoke(realm); }
    Object ownViaThis(String realm) { return this.invoke(realm); }
    Object ownViaSuper(String realm) { return super.invoke(realm); }
    Object noArgument(Helper h) { return h.invoke(); }
    Object freshReceiver(String realm) { return new Helper().invoke(realm, realm); }

    // Safe: empty StringSubstitutor — no interpolator factory — CVE-2022-42889 fix shape.
    String safeStringSubstitutorPassthrough(String input) {
        StringSubstitutor s = new StringSubstitutor();
        return s.replace(input);
    }
}
