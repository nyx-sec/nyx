"""Phase 06 (Track J.4) — Python LDAP_INJECTION vuln fixture.

The function string-concatenates the attacker-controlled `uid` into the
LDAP filter passed to `ldap.search_s`; a payload like `alice*)(uid=*`
breaks out of the host `(uid=…)` clause and matches every directory
entry.
"""
import ldap


def run(uid: str):
    con = ldap.initialize("ldap://127.0.0.1")
    filt = "(uid=" + uid + ")"
    return con.search_s("ou=people,dc=nyx,dc=test", ldap.SCOPE_SUBTREE, filt)
