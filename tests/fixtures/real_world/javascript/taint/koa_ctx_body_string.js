const Router = require('@koa/router');

const router = new Router();

router.get('/greet', async (ctx) => {
  const name = ctx.query.name;
  ctx.body = '<html><h1>Hello ' + name + '</h1></html>';
});

module.exports = router;
