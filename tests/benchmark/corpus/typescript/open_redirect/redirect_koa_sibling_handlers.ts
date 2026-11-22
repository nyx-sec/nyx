// A request-derived redirect target still fires next to sibling handlers.
import Router from "koa-router";
import { Context } from "koa";

const router = new Router();

router.get("a", async (ctx: Context) => {
  ctx.state.seen = true;
});

router.get("b", async (ctx: Context) => {
  ctx.redirect(ctx.query.next as string);
});

export default router;
