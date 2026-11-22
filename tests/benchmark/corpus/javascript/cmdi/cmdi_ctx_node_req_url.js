// The request URL read through a long receiver chain reaches a shell command.
const cp = require('child_process');

function handler(ctx) {
  cp.exec('curl ' + ctx.node.req.url);
}
