// Unsafe: ldapjs `client.search` receives a filter assembled from req.query.
// Bound-variable idiom: the closure-captured `client` carries
// `TypeKind::LdapClient` (forwarded from the top-level body to the function
// body by `taint::inject_external_type_facts`), so type-qualified receiver
// resolution rewrites `client.search` → `LdapClient.search`.
import * as ldap from 'ldapjs';

const client = ldap.createClient({ url: 'ldap://example.com' });

export function lookup(req: any, res: any) {
    const user = req.query.user;
    const filter = '(uid=' + user + ')';
    client.search('ou=people,dc=example,dc=com', { filter: filter }, (err: any) => { res.json({ ok: !err }); });
}
