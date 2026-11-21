const Koa = require('koa');
const { execSync } = require('child_process');

const app = new Koa();
const ALLOWED = ['ls', 'pwd'];

app.use(async (ctx) => {
  const cmd = ctx.query.cmd;
  if (!ALLOWED.includes(cmd)) {
    ctx.throw(400, 'bad command');
  }
  ctx.body = String(execSync(cmd));
});
