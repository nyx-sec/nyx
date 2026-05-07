/* Safe: project-local sanitize_ldap_filter (matches the developer-named
 * `sanitize_*` Sanitizer rule) clears caps on the user value before it
 * reaches ldap_search_ext_s. */
#include <ldap.h>
#include <stdlib.h>

extern char *sanitize_ldap_filter(const char *raw);

int do_lookup(LDAP *ld) {
    char *user_filter = getenv("USER_FILTER");
    char *safe = sanitize_ldap_filter(user_filter);
    LDAPMessage *res = NULL;
    return ldap_search_ext_s(
        ld,
        "ou=people,dc=example,dc=com",
        LDAP_SCOPE_SUBTREE,
        safe,
        NULL, 0, NULL, NULL, NULL, 0, &res);
}
