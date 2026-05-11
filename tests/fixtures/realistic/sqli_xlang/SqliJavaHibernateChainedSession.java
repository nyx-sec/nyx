// Hibernate `session.createNativeQuery(sql).getResultList()` SQLi
// where the receiver `sess` is bound from `sessionFactory.openSession()`
// AND the query call is followed by a `.getResultList()` (or other
// terminator) so the outer SSA Call is the terminator and the
// `createNativeQuery` sits as a chained inner call.  The CFG-time
// receiver-type rewrite (in `find_classifiable_inner_call`) consults
// the per-file local-receiver-types map populated at `build_cfg`
// start to rewrite `sess.createNativeQuery` →
// `HibernateSession.createNativeQuery`, matching the type-qualified
// rule in `labels/java.rs`.
package com.example;

import javax.servlet.http.HttpServletRequest;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import java.util.List;

public class SqliJavaHibernateChainedSession {
    public void lookup(HttpServletRequest request, SessionFactory sf) {
        String name = request.getParameter("name");
        String sql = String.format("SELECT * FROM users WHERE name = '%s'", name);
        Session sess = sf.openSession();
        List<?> rows = sess.createNativeQuery(sql).getResultList();
    }
}
