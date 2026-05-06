// Baseline: filter is a literal constant; no taint reaches the search call.
const ldap = require('ldapjs');

const client = ldap.createClient({ url: 'ldap://example.com' });

function lookup(_req, res) {
    const filter = '(objectClass=person)';
    client.search('ou=people,dc=example,dc=com', { filter: filter }, (err) => { res.json({ ok: !err }); });
}

module.exports = lookup;
