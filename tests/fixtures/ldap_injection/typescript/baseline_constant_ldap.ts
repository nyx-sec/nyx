// Baseline: filter is a literal constant; no taint reaches the search call.
import * as ldap from 'ldapjs';

const client = ldap.createClient({ url: 'ldap://example.com' });

export function lookup(_req: any, res: any) {
    const filter = '(objectClass=person)';
    client.search('ou=people,dc=example,dc=com', { filter: filter }, (err: any) => { res.json({ ok: !err }); });
}
