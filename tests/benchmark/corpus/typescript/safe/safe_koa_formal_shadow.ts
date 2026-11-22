// The ctx formal of one handler is not the ctx formal of a sibling handler.
import Router from "koa-router";
import { Context } from "koa";
import env from "./env";

const router = new Router();

router.get("a", async (ctx: Context) => {
  ctx.state.base = process.env.PUBLIC_URL;
});

router.get("b", async (ctx: Context) => {
  ctx.redirect(`${env.URL}?x=1`);
});

export default router;
