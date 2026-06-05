<?php
// Phase 06 (Track J.4) — PHP LDAP_INJECTION benign control fixture.
//
// Same shape as `vuln.php` but routes the attacker-controlled `$uid`
// through `ldap_escape($uid, "", LDAP_ESCAPE_FILTER)`, escaping the
// wildcard / paren breakout so the directory keeps returning at most
// one entry.
function run(string $uid) {
    $c = ldap_connect("127.0.0.1");
    ldap_bind($c);
    $filter = "(uid=" . ldap_escape($uid, "", LDAP_ESCAPE_FILTER) . ")";
    return ldap_search($c, "ou=people,dc=nyx,dc=test", $filter);
}
