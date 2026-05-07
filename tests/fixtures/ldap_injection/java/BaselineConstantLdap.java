// Baseline: the filter is a compile-time constant; no taint reaches the sink
// and no LDAP_INJECTION finding fires.  Guards the rule against firing on
// safe-by-construction call sites that simply happen to hit a search API.
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;

public class BaselineConstantLdap {
    private DirContext ctx;

    public Object lookup() throws Exception {
        String filter = "(objectClass=person)";
        return ctx.search("ou=people,dc=example,dc=com", filter, new SearchControls());
    }
}
