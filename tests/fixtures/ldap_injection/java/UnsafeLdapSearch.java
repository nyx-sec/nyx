// Unsafe: attacker-controlled username concatenated into an LDAP filter passed
// to DirContext.search.  The receiver `ctx` carries TypeKind::LdapClient via
// the declared `DirContext` type so type-qualified resolution rewrites the
// callee to `LdapClient.search` and the LDAP_INJECTION sink fires.
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;

public class UnsafeLdapSearch {
    private DirContext ctx;

    public Object lookup(HttpServletRequest req) throws Exception {
        String user = req.getParameter("user");
        String filter = "(uid=" + user + ")";
        return ctx.search("ou=people,dc=example,dc=com", filter, new SearchControls());
    }
}
