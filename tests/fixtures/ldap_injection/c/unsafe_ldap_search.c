/* Unsafe: tainted env-string passed straight as the LDAP filter argument
 * to ldap_search_ext_s.  LDAP_INJECTION fires on the filter (arg 3). */
#include <ldap.h>
#include <stdlib.h>

int do_lookup(LDAP *ld) {
    char *user_filter = getenv("USER_FILTER");
    LDAPMessage *res = NULL;
    return ldap_search_ext_s(
        ld,
        "ou=people,dc=example,dc=com",
        LDAP_SCOPE_SUBTREE,
        user_filter,
        NULL, 0, NULL, NULL, NULL, 0, &res);
}
