module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('users', {});
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('users');
  },
};

function normalizeName(name) {
  return String(name);
}

module.exports.normalizeName = normalizeName;
