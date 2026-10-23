// Koa handlers whose authenticated actor comes from `ctx.state.auth` or
// `ctx.state.user`.  The actor's own id and own team are not foreign ids.
// Pinned in `auth_analysis_tests`.
import Router from "@koa/router";

const router = new Router();

router.post("integrations.create", async (ctx) => {
  const { user } = ctx.state.auth;
  await Integration.create({ userId: user.id, teamId: user.teamId });
  const team = await Team.findByPk(user.teamId);
  ctx.body = { team };
});

router.get("team.info", async (ctx) => {
  const user = ctx.state.user;
  const team = await Team.findByPk(user.teamId);
  ctx.body = { team };
});

export default router;
