"""Phase 06 (Track J.4) — Python LDAP_INJECTION benign control fixture.

Same shape as `vuln.py` but routes the attacker-controlled `uid`
through `ldap.dn.escape_filter_chars`, escaping the wildcard /
paren breakout so the directory keeps returning at most one entry.
"""
import ldap
import ldap.dn


def run(uid: str):
    con = ldap.initialize("ldap://127.0.0.1")
    filt = "(uid=" + ldap.dn.escape_filter_chars(uid) + ")"
    return con.search_s("ou=people,dc=nyx,dc=test", ldap.SCOPE_SUBTREE, filt)
