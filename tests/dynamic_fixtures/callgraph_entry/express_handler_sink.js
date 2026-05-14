// Phase 04 fixture: Express route handler is a named function bound at
// `app.post`; it calls a helper that holds the sink. The callgraph-aware
// spec-derivation path must rewrite the harness entry to the route
// handler `runCommand`, not the helper `execHelper`.
//
// `runCommand` reads `req.body.cmd` into a local before dispatching to
// `execHelper`. Threading the local through gives the JS callee
// extractor a clean call shape (bare identifier in argument position)
// so the call-graph picks up the `runCommand → execHelper` edge.

const express = require("express");
const { exec } = require("child_process");

const app = express();

function execHelper(cmd) {
  exec(cmd); // sink: command injection
}

function runCommand(req, res) {
  const cmd = req.body.cmd;
  execHelper(cmd);
  res.send("ok");
}

app.post("/run", runCommand);

module.exports = app;
