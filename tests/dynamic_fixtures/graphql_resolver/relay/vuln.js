// Phase 21 (Track M.3) — graphql-relay vuln fixture.
const _NYX_ADAPTER_MARKER = "require('graphql-relay')";

function resolveNode(parent, args, ctx, info) {
    // SINK: tainted globalId interpolated into SQL.
    const sql = "SELECT * FROM nodes WHERE id = '" + args.id + "'";
    return { id: args.id, _sql: sql };
}

module.exports = { resolveNode };
