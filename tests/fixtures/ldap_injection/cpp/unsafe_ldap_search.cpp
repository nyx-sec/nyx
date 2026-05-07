// Unsafe: tainted env value passed straight as the LDAP filter argument to
// ldap_search_ext_s.  LDAP_INJECTION fires on the filter argument (position 3).
#include <cstdlib>
#include <ldap.h>

int do_lookup(LDAP* ld) {
    const char* user_filter = std::getenv("USER_FILTER");
    LDAPMessage* res = nullptr;
    return ldap_search_ext_s(
        ld,
        "ou=people,dc=example,dc=com",
        LDAP_SCOPE_SUBTREE,
        user_filter,
        nullptr, 0, nullptr, nullptr, nullptr, 0, &res);
}
