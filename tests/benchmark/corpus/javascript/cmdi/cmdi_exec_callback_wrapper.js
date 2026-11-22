const { exec } = require("child_process");

function handler(req, res) {
  exec(req.query.c, (error, stdout) => {
    res.send(stdout);
  });
}

function handlerNamed(req, res) {
  const cmd = req.body.cmd;
  exec(cmd, done);
}

function done() {}

module.exports = { handler, handlerNamed };
