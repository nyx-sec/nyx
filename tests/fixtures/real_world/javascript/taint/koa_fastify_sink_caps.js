const Koa = require('koa');
const Router = require('@koa/router');
const fastify = require('fastify')();

const router = new Router();

router.get('/go', async (ctx) => {
  ctx.redirect(ctx.query.next);
});

router.get('/trace', async (ctx) => {
  ctx.set('X-Trace', ctx.query.t);
});

router.get('/name', async (ctx) => {
  ctx.response.body = ctx.request.query.name;
});

fastify.get('/go', async (request, reply) => {
  return reply.redirect(request.query.next);
});

fastify.get('/trace', async (request, reply) => {
  reply.header('X-Trace', request.query.t);
  return 'ok';
});

module.exports = { router, fastify };
