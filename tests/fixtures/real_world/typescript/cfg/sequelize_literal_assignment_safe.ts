import { Sequelize, Op } from "sequelize";
import { Document } from "./models";

export async function search(query: string, userId: string | undefined) {
  let where: any = { teamId: 1 };
  if (query) {
    where = {
      ...where,
      [Op.and]: [
        Sequelize.literal(`unaccent(LOWER(name)) like unaccent(LOWER(:query))`),
      ],
    };
  }
  if (userId) {
    where = { ...where, id: userId };
  }
  return Document.findAll({ where, replacements: { query: `%${query}%` } });
}
