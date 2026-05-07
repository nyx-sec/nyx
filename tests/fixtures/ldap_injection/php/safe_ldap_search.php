<?php
// Safe: ldap_escape() with LDAP_ESCAPE_FILTER (or default) sanitises the user
// substring before it lands in the filter.  Sanitizer(LDAP_INJECTION) clears
// the cap so the sink does not fire.
$ds = ldap_connect("ldap://example.com");
$user = $_GET['user'];
$safe = ldap_escape($user, "", LDAP_ESCAPE_FILTER);
$filter = "(uid=" . $safe . ")";
$result = ldap_search($ds, "ou=people,dc=example,dc=com", $filter);
