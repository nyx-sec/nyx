// Phase 06 (Track J.4) — Java LDAP_INJECTION benign control fixture.
//
// Same shape as `Vuln.java` but routes the attacker-controlled `uid`
// through `org.springframework.ldap.support.LdapEncoder.filterEncode`
// before splicing it into the filter, so any wildcard / paren breakout
// is escaped and the directory keeps returning at most one entry.
import java.util.List;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.support.LdapEncoder;

public class Benign {
    public static List<Object> run(String uid, LdapTemplate template) {
        String filter = "(uid=" + LdapEncoder.filterEncode(uid) + ")";
        return template.search("ou=people,dc=nyx,dc=test", filter, null);
    }
}
