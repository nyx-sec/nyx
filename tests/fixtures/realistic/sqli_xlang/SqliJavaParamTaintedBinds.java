// Phase 15 deferred-fix negative — Java JPA parameterised query with
// TAINTED bind value.  The JPQL string at arg 0 of
// `entityManager.createQuery` is a literal; the user-controlled `name`
// is bound via `setParameter`, which the JPA layer escapes through the
// JDBC parameterised path.  Without payload-arg gating on
// `entityManager.createQuery` (Phase 15 deferred fix in
// `labels/java.rs::GATED_SINKS`), the flat rule's all-arg activation
// combined with `setParameter`'s arg→return propagation could surface a
// SQL_QUERY finding on the chain.  The Destination gate restricts
// `sink_payload_args` to `&[0]`, narrowing the scan to the JPQL string.
package com.example;

import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.servlet.http.HttpServletRequest;

public class SqliJavaParamTaintedBinds {
    public Object lookup(HttpServletRequest request, EntityManager entityManager) {
        String name = request.getParameter("name");
        Query q = entityManager.createQuery("SELECT u FROM User u WHERE u.name = :name");
        q.setParameter("name", name);
        return q.getResultList();
    }
}
