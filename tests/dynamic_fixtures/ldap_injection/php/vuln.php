<?php
// Phase 06 (Track J.4) — PHP LDAP_INJECTION vuln fixture.
//
// The function string-concatenates the attacker-controlled `$uid` into
// the LDAP filter passed to `ldap_search`; a payload like
// `alice*)(uid=*` breaks out of the host `(uid=…)` clause and matches
// every directory entry.
function run(string $uid) {
    $c = ldap_connect("127.0.0.1");
    ldap_bind($c);
    $filter = "(uid=" . $uid . ")";
    return ldap_search($c, "ou=people,dc=nyx,dc=test", $filter);
}
