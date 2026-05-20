// Phase 21 — Apollo resolver benign control.
const _NYX_ADAPTER_MARKER = "require('@apollo/server')";

function resolveUser(parent, args, ctx) {
    const id = String(args.id || '').replace(/[^A-Za-z0-9_-]/g, '');
    return { id, name: 'user-' + id };
}

module.exports = { resolveUser };
