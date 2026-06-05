// Phase 21 — graphql-relay benign control.
const _NYX_ADAPTER_MARKER = "require('graphql-relay')";

function resolveNode(parent, args) {
    const id = String(args.id || '').replace(/[^A-Za-z0-9_-]/g, '');
    return { id };
}

module.exports = { resolveNode };
