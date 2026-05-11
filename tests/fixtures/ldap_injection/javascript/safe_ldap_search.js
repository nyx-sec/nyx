// Safe: ldap-escape's `filter` helper escapes the user-controlled substring
// before it lands in the filter expression.  Mirrors the unsafe sibling's
// bound-variable shape so only the sanitiser introduction differs.
const ldap = require('ldapjs');
const ldapEscape = require('ldap-escape');

const client = ldap.createClient({ url: 'ldap://example.com' });

function lookup(req, res) {
    const user = req.query.user;
    const safe = ldapEscape(user);
    const filter = '(uid=' + safe + ')';
    client.search('ou=people,dc=example,dc=com', { filter: filter }, (err) => { res.json({ ok: !err }); });
}

module.exports = lookup;
