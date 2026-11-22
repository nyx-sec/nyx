const names = ["a", "b"];
names.push(process.env.EXTRA_TABLE);
const fixed = ["x", "y"];

function dropAll(sequelize) {
  for (const name of names) {
    sequelize.query(`drop table "${name}"`);
  }
}

function dropOne(suffix) {
  for (const name of fixed) {
    sequelize.query(`drop table "${name}_${suffix}" cascade`);
  }
}

module.exports = { dropAll, dropOne };
