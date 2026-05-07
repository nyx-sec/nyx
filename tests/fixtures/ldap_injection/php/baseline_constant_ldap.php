<?php
// Baseline: filter is a literal string, no taint reaches the sink.
$ds = ldap_connect("ldap://example.com");
$result = ldap_search($ds, "ou=people,dc=example,dc=com", "(objectClass=person)");
