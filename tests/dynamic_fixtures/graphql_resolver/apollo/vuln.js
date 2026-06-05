// Phase 21 (Track M.3) — Apollo GraphQL resolver vuln fixture.
//
// `resolveUser(parent, args)` is a resolver from an Apollo schema that
// splices `args.id` into a SQL query via raw string concatenation —
// classic GraphQL → SQLi shape.
const _NYX_ADAPTER_MARKER = "require('@apollo/server')";

function resolveUser(parent, args, ctx) {
    // SINK: tainted args.id concatenated into SQL.
    const query = "SELECT * FROM users WHERE id = '" + args.id + "'";
    return { id: args.id, name: 'user-' + args.id, _query: query };
}

module.exports = { resolveUser };
