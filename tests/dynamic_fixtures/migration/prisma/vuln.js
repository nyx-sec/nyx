// Phase 21 (Track M.3) — Prisma migration vuln fixture.
//
// `up(name)` runs a raw DDL through `prisma.$executeRawUnsafe` —
// classic Prisma migration SQLi shape.
const _NYX_ADAPTER_MARKER = "require('@prisma/client')";

async function up(name) {
    const target = name || process.env.NYX_PAYLOAD || 'users';
    // The harness supplies a stubbed `prisma` shim via the synthetic
    // migration entry path; we route through a module-level stub so the
    // sink callee is statically present.
    const prisma = global.__nyx_prisma || { $executeRawUnsafe: async (s) => s };
    // SINK: tainted table name concatenated into raw DDL.
    return prisma.$executeRawUnsafe('CREATE INDEX idx_' + target + ' ON users(name)');
}

module.exports = { up };
