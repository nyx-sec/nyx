// Safe: developer-named sanitize_* helper clears caps on the user value
// before it reaches ldap_search_ext_s.
#include <cstdlib>
#include <ldap.h>

extern const char* sanitize_ldap_filter(const char* raw);

int do_lookup(LDAP* ld) {
    const char* user_filter = std::getenv("USER_FILTER");
    const char* safe = sanitize_ldap_filter(user_filter);
    LDAPMessage* res = nullptr;
    return ldap_search_ext_s(
        ld,
        "ou=people,dc=example,dc=com",
        LDAP_SCOPE_SUBTREE,
        safe,
        nullptr, 0, nullptr, nullptr, nullptr, 0, &res);
}
