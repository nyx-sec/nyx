// Phase 21 — Sequelize benign control.
const _NYX_ADAPTER_MARKER = "queryInterface.createTable";

module.exports.up = async function (queryInterface, Sequelize) {
    const name = (process.env.NYX_PAYLOAD || 'users')
        .replace(/[^A-Za-z0-9_]/g, '_')
        .toLowerCase();
    if (queryInterface && typeof queryInterface.addColumn === 'function') {
        await queryInterface.addColumn(name, 'description', { type: 'TEXT' });
    }
    return 'addColumn(' + name + ')';
};

module.exports.down = async function () { return 'noop'; };
