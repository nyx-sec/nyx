import { Sequelize, Op } from "sequelize";
import { Document } from "./models";

export async function search(req: any) {
  const term = req.query.q;
  let where: any = {};
  where = {
    [Op.and]: [Sequelize.literal(`name like '%${term}%'`)],
  };
  return Document.findAll({ where });
}
