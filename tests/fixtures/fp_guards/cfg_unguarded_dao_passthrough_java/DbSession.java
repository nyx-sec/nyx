package org.openmrs.api.db.hibernate;

public class DbSession {
    public Object createQuery(String queryString) {
        return getSession().createQuery(queryString);
    }

    public Object createSQLQuery(String queryString, Class type) {
        return getSession().createNativeQuery(queryString, type);
    }

    public Object createCriteria(Class persistentClass) {
        return getSession().getCriteriaBuilder().createQuery(persistentClass);
    }
}
