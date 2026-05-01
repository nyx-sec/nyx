// Regression guard for the for-of-with-array-destructure taint propagation
// fix: `for (const [a, b] of Object.entries(tainted))` must propagate the
// iterable's taint to the destructured bindings, otherwise patterns like
// the docker.ts shell-injection (where filePath is bound by destructure-iter
// from a tainted parameter) silently lose the flow.
import express from "express";
const app = express();
const { exec } = require("child_process");

app.post("/files", async (req: any, res: any) => {
  const files = req.body.files;
  for (const [filePath, content] of Object.entries(files)) {
    // TP: filePath is destructured from Object.entries(files) where files
    // carries taint.  Without the for-of pattern handler the binding
    // is never registered as a definition and taint stops at `files`.
    exec(`rm -rf /tmp/${filePath}`);
  }
  res.send("ok");
});
