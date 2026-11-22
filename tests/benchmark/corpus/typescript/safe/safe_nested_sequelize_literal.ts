import { Sequelize, Op } from "sequelize";
import { User, Group } from "./models";

export async function list(term: string) {
  const [users, groups] = await Promise.all([
    User.findAll({
      where: {
        active: true,
        [Op.and]: term
          ? { [Op.or]: [Sequelize.literal(`unaccent(LOWER(email)) like unaccent(LOWER(:term))`)] }
          : {},
      },
      replacements: { term: `%${term}%` },
    }),
    Group.findAll({ where: { active: true } }),
  ]);
  return { users, groups };
}

export async function single(term: string) {
  return User.findAll({
    where: {
      [Op.and]: Sequelize.literal(`unaccent(LOWER(name)) like unaccent(LOWER(:term))`),
    },
    replacements: { term: `%${term}%` },
  });
}
