const tableName = "revisions";
const constraintNames = ["revisions_documentId_fkey", "documentId_foreign_idx"];

module.exports = {
  up: async (queryInterface, Sequelize) => {
    for (const constraintName of constraintNames) {
      await queryInterface.sequelize.query(
        `alter table "${tableName}" drop constraint "${constraintName}"`
      );
    }
  },
};
