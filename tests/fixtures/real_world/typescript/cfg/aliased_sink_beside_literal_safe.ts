import { Sequelize } from "sequelize";
import { User } from "./models";

export function f(term: string) {
  const lit = Sequelize.literal;
  return User.findAll({
    where: Sequelize.literal("a"),
    x: lit("b"),
    replacements: { term },
  });
}
