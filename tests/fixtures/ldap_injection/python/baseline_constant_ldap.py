# Baseline: filter is a compile-time constant.  No taint reaches `search_s` so
# no LDAP_INJECTION finding fires.
import ldap


def lookup():
    conn = ldap.initialize("ldap://example.com")
    return conn.search_s(
        "ou=people,dc=example,dc=com", ldap.SCOPE_SUBTREE, "(objectClass=person)"
    )
