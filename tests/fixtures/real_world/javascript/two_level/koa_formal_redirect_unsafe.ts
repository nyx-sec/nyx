// Same sibling layout, but the redirect target really comes from the request.
import Router from "koa-router";

const router = new Router();

router.get("a", async (ctx: any) => {
  ctx.body = "x";
});

router.get("b", async (ctx: any) => {
  ctx.redirect(ctx.query.next);
});

export default router;
