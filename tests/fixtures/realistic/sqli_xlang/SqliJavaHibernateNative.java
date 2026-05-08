// Phase 15 — Hibernate `session.createNativeQuery` interpolation SQLi
// positive.  `session.createNativeQuery` is a flat SQL_QUERY sink in
// `labels/java.rs`; the `String.format` call interpolates the user-
// controlled name into the SQL string with no parameterisation.
package com.example;

import javax.servlet.http.HttpServletRequest;
import org.hibernate.Session;

public class SqliJavaHibernateNative {
    public Object lookup(HttpServletRequest request, Session session) {
        String name = request.getParameter("name");
        String sql = String.format("SELECT * FROM users WHERE name = '%s'", name);
        return session.createNativeQuery(sql).getResultList();
    }
}
