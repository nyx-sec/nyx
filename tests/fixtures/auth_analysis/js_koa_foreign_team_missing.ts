// Recall guard for `js_koa_state_auth_clean.ts`: a team id taken from the
// request body is foreign.  Pinned in `auth_analysis_tests`.
import Router from "@koa/router";

const router = new Router();

router.post("team.info", async (ctx) => {
  const team = await Team.findByPk(ctx.input.body.teamId);
  ctx.body = { team };
});

export default router;
