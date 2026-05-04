import jakarta.persistence.EntityManager;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;
import org.hibernate.Session;
import java.util.List;

// Distilled from openmrs's
// api/src/main/java/org/openmrs/api/db/hibernate/HibernateCohortDAO.java
// (`getCohorts` / `getCohort`) and HibernateAdministrationDAO.  The JPA
// CriteriaBuilder pattern builds a structural `CriteriaQuery<Foo>` via
// `cb.createQuery(Foo.class)` plus `Root` / `Predicate` / `cb.equal` /
// `cb.like` etc., then hands the structural query object to
// `session.createQuery(cq)` / `em.createQuery(cq)` for execution.  No
// string concatenation occurs — JPA emits parameterized SQL by
// construction.  Engine must propagate the
// `TypeKind::JpaCriteriaQuery` fact through the `cb.createQuery`
// receiver-text recogniser, then suppress the structural
// `cfg-unguarded-sink` finding at the `session.createQuery(cq)` /
// `em.createQuery(cq)` site via `sink_args_jpa_criteria_query_safe`.
public class SafeJpaCriteriaQuery {
    private final Session session;
    private final EntityManager em;

    public SafeJpaCriteriaQuery(Session session, EntityManager em) {
        this.session = session;
        this.em = em;
    }

    public List<Cohort> getCohorts(String nameFragment) {
        CriteriaBuilder cb = session.getCriteriaBuilder();
        CriteriaQuery<Cohort> cq = cb.createQuery(Cohort.class);
        Root<Cohort> root = cq.from(Cohort.class);
        cq.where(cb.like(cb.lower(root.get("name")), nameFragment));
        return session.createQuery(cq).getResultList();
    }

    public Cohort getCohortByName(String name) {
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<Cohort> cq = cb.createQuery(Cohort.class);
        Root<Cohort> root = cq.from(Cohort.class);
        cq.where(cb.equal(root.get("name"), name));
        return em.createQuery(cq).getSingleResult();
    }

    public static class Cohort {}
}
