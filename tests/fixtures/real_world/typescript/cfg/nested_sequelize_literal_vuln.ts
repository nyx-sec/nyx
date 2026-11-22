import { Sequelize, Op } from "sequelize";
import { User } from "./models";

export async function direct(req: any) {
  const q = req.query.q;
  return User.findAll({ where: Sequelize.literal(`name = '${q}'`) });
}

export async function mixed(req: any) {
  const q = req.query.q;
  return User.findAll({
    where: { [Op.or]: [Sequelize.literal(`active = true`), Sequelize.literal(`name = '${q}'`)] },
  });
}
