// Phase 21 (Track M.3) — Sequelize migration vuln fixture.
//
// `up(queryInterface, Sequelize)` is the canonical migration entry
// point.  This fixture builds a raw DDL string from an attacker-
// controlled table name and routes it through `queryInterface.sequelize.query`.
const _NYX_ADAPTER_MARKER = "queryInterface.createTable";

module.exports.up = async function (queryInterface, Sequelize) {
    const name = process.env.NYX_PAYLOAD || 'users';
    // SINK: tainted table name concatenated into raw DDL.
    const sql = 'CREATE INDEX idx_' + name + ' ON users(name)';
    if (queryInterface && queryInterface.sequelize && queryInterface.sequelize.query) {
        await queryInterface.sequelize.query(sql);
    }
    return sql;
};

module.exports.down = async function (queryInterface, Sequelize) {
    // benign in the down direction.
    return 'DROP INDEX idx_users';
};
