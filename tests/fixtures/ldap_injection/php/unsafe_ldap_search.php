<?php
// Unsafe: $_GET['user'] concatenated into an LDAP filter and passed straight
// to ldap_search.  LDAP_INJECTION fires on the filter argument.
$ds = ldap_connect("ldap://example.com");
$user = $_GET['user'];
$filter = "(uid=" . $user . ")";
$result = ldap_search($ds, "ou=people,dc=example,dc=com", $filter);
