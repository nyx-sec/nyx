/* Baseline: filter is a string literal, no LDAP_INJECTION finding. */
#include <ldap.h>

int do_lookup(LDAP *ld) {
    LDAPMessage *res = NULL;
    return ldap_search_ext_s(
        ld,
        "ou=people,dc=example,dc=com",
        LDAP_SCOPE_SUBTREE,
        "(objectClass=person)",
        NULL, 0, NULL, NULL, NULL, 0, &res);
}
