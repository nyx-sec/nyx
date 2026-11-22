const NAMES = ["a", "b"];

function dropAll(sequelize) {
  for (const name of NAMES) {
    sequelize.query(`drop table "${name}"`);
  }
}

module.exports = { dropAll };
