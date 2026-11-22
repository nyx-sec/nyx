import { Sequelize } from "sequelize";
import { User } from "./models";

export function f(req: any, q: string) {
  const lit = Sequelize.literal;
  return User.findAll({ where: Sequelize.literal("a"), x: lit(q) });
}
