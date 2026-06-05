// Phase 06 (Track J.4) — Java LDAP_INJECTION vuln fixture.
//
// The function string-concatenates the attacker-controlled `uid`
// directly into the LDAP filter passed to `LdapTemplate.search`.  A
// payload like `alice*)(uid=*` rewraps the filter as
// `(|(uid=alice*)(uid=*))` once the host wrapper pushes it through a
// containing `(|…)`/`(&…)` clause, matching every directory entry.
import java.util.List;
import org.springframework.ldap.core.LdapTemplate;

public class Vuln {
    public static List<Object> run(String uid, LdapTemplate template) {
        String filter = "(uid=" + uid + ")";
        return template.search("ou=people,dc=nyx,dc=test", filter, null);
    }
}
