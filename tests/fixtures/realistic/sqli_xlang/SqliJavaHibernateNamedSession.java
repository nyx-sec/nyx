// Hibernate `session.createNativeQuery` SQLi via arbitrary-named
// receiver bound from `sessionFactory.openSession()`.  The flat
// `session.createNativeQuery` matcher in `labels/java.rs` only fires
// when the receiver is literally named `session`; for any other name
// (`sess` here) the type-qualified `HibernateSession.createNativeQuery`
// rule fires via the `TypeKind::HibernateSession` fact attached to the
// SSA value returned by `sessionFactory.openSession()`.
package com.example;

import javax.servlet.http.HttpServletRequest;
import org.hibernate.Session;
import org.hibernate.SessionFactory;

public class SqliJavaHibernateNamedSession {
    public void lookup(HttpServletRequest request, SessionFactory sf) {
        String name = request.getParameter("name");
        String sql = String.format("SELECT * FROM users WHERE name = '%s'", name);
        Session sess = sf.openSession();
        sess.createNativeQuery(sql);
    }
}
