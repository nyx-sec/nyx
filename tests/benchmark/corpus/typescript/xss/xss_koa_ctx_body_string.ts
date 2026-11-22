import Router from '@koa/router';

const router = new Router();

router.get('/greet', async (ctx) => {
  const name = ctx.query.name as string;
  ctx.body = `<html><h1>Hello ${name}</h1></html>`;
});

export default router;
