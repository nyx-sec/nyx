// The `ctx` formal of one handler is not the `ctx` of a sibling handler:
// tainted writes through one must not seed the other.
import Router from "koa-router";
import env from "./env";

const router = new Router();

router.get("a", async (ctx: any) => {
  ctx.state.base = process.env.PUBLIC_URL;
});

router.get("b", async (ctx: any) => {
  ctx.redirect(`${env.URL}?x=1`);
});

export default router;
