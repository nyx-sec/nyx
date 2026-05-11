// Phase 15 negative — JPA parameterised query.  `setParameter` is a
// SQL_QUERY sanitizer in `labels/java.rs`, but the deciding factor for
// this fixture is that the SQL template fed to `entityManager
// .createQuery` is a constant — no taint reaches the sink.  Bind
// values are constants too, mirroring phase 07's safe-parameterised
// approach.
package com.example;

import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.servlet.http.HttpServletRequest;

public class SqliJavaParamSafe {
    public Object lookup(HttpServletRequest request, EntityManager entityManager) {
        String _unused = request.getParameter("name");
        Query q = entityManager.createQuery("SELECT u FROM User u WHERE u.id = :id");
        q.setParameter("id", 1L);
        return q.getResultList();
    }
}
