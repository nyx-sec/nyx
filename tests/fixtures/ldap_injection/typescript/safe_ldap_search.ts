// Safe: ldap-escape's `filter` helper escapes the user-controlled substring
// before it lands in the filter expression.  Mirrors the unsafe sibling's
// bound-variable shape so only the sanitiser introduction differs.
import * as ldap from 'ldapjs';
import ldapEscape from 'ldap-escape';

const client = ldap.createClient({ url: 'ldap://example.com' });

export function lookup(req: any, res: any) {
    const user = req.query.user;
    const safe = ldapEscape(user);
    const filter = '(uid=' + safe + ')';
    client.search('ou=people,dc=example,dc=com', { filter: filter }, (err: any) => { res.json({ ok: !err }); });
}
