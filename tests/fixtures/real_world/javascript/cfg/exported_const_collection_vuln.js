export const NAMES = ["a", "b"];

export function dropAll(sequelize) {
  for (const name of NAMES) {
    sequelize.query(`drop table "${name}"`);
  }
}
