# Unsafe: tainted form data concatenated into an LDAP filter and passed to
# python-ldap's `search_s`.  The bound receiver `conn` is typed as LdapClient
# via `ldap.initialize`, and the suffix matcher on `search_s` also catches the
# call directly.
import ldap
from flask import request


def lookup():
    conn = ldap.initialize("ldap://example.com")
    user = request.form["user"]
    flt = "(uid=" + user + ")"
    return conn.search_s("ou=people,dc=example,dc=com", ldap.SCOPE_SUBTREE, flt)
