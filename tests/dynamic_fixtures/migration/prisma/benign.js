// Phase 21 — Prisma migration benign control.
const _NYX_ADAPTER_MARKER = "require('@prisma/client')";

async function up(name) {
    const safe = String(name || process.env.NYX_PAYLOAD || 'users')
        .replace(/[^A-Za-z0-9_]/g, '_')
        .toLowerCase();
    const prisma = global.__nyx_prisma || { $executeRawUnsafe: async (s) => s };
    return prisma.$executeRawUnsafe('CREATE INDEX idx_' + safe + ' ON users(name)');
}

module.exports = { up };
