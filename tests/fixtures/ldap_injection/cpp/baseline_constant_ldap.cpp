// Baseline: literal filter, no taint reaches the sink.
#include <ldap.h>

int do_lookup(LDAP* ld) {
    LDAPMessage* res = nullptr;
    return ldap_search_ext_s(
        ld,
        "ou=people,dc=example,dc=com",
        LDAP_SCOPE_SUBTREE,
        "(objectClass=person)",
        nullptr, 0, nullptr, nullptr, nullptr, 0, &res);
}
