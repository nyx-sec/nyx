const cp = require('child_process');
const config = require('./config');

function h(req) {
  for (const f of req.body.items) {
    cp.exec('ls ' + f);
  }
}

function h2(req) {
  for (const f of req.body.items) {
    const c = 'ls ' + f;
    cp.exec(c);
  }
}

function fixed() {
  for (const f of config.items) {
    cp.exec('ls ' + f);
  }
}

module.exports = { h, h2, fixed };
