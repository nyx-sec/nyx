const Router = require('@koa/router');

const router = new Router();

// Koa serialises an object or array body as application/json.
router.get('/greet', async (ctx) => {
  const name = ctx.query.name;
  ctx.body = { greeting: 'Hello', name: name };
});

router.get('/names', async (ctx) => {
  const name = ctx.query.name;
  ctx.body = [name];
});

module.exports = router;
