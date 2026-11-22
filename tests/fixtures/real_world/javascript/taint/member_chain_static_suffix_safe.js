// Long chains that merely end in a source suffix are not request input.
const cp = require('child_process');

function fromLiteral() {
  const o = { a: { b: { req: { url: 'static' } } } };
  cp.exec('ls ' + o.a.b.req.url);
}

function fromConfig() {
  const cfg = require('./cfg');
  cp.exec('ls ' + cfg.x.y.req.url);
  cp.exec('ls ' + cfg.x.y.req.body);
  cp.exec('ls ' + cfg.x.y.process.env.HOME);
  cp.exec('ls ' + cfg.x.y.document.location);
}
