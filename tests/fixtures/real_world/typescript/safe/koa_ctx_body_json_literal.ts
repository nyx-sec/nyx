import Router from '@koa/router';

const router = new Router();

// Koa serialises an object or array body as application/json.
router.get('/greet', async (ctx) => {
  const name = ctx.query.name as string;
  ctx.body = { greeting: 'Hello', name };
});

router.get('/names', async (ctx) => {
  const name = ctx.query.name as string;
  ctx.body = [name];
});

export default router;
