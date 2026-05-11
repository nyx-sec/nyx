# Safe: user-supplied substring run through `escape_filter_chars` (RFC 4515)
# before being concatenated into the filter.  The sanitizer clears the
# LDAP_INJECTION cap so the sink does not fire.
import ldap
from ldap.filter import escape_filter_chars
from flask import request


def lookup():
    conn = ldap.initialize("ldap://example.com")
    user = request.form["user"]
    safe = escape_filter_chars(user)
    flt = "(uid=" + safe + ")"
    return conn.search_s("ou=people,dc=example,dc=com", ldap.SCOPE_SUBTREE, flt)
