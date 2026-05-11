// Safe: the user-supplied substring is run through Spring LDAP's
// LdapEncoder.filterEncode (RFC 4515 escape) before being assembled into the
// filter.  The Sanitizer(LDAP_INJECTION) clears the cap and the sink does not
// fire.
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;
import org.springframework.ldap.support.LdapEncoder;

public class SafeLdapSearch {
    private DirContext ctx;

    public Object lookup(HttpServletRequest req) throws Exception {
        String user = req.getParameter("user");
        String safe = LdapEncoder.filterEncode(user);
        String filter = "(uid=" + safe + ")";
        return ctx.search("ou=people,dc=example,dc=com", filter, new SearchControls());
    }
}
