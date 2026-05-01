// Reproduces the docker.ts pattern: a user-defined wrapper passes a shell-array
// literal to an opaque helper that ultimately invokes the shell.  The taint
// vector is the third array element (the shell command string) — single-quote
// escaping in the interpolated `name` breaks out of the surrounding `'...'`
// and runs arbitrary commands.  Detection must fire at the wrapper call site
// without needing any summary annotation on `runShellWrapper`.
import express from "express";
const app = express();

async function runShellWrapper(_id: string, _cmd: string[]): Promise<string> {
  // Opaque wrapper.  In real code this dispatches to Dockerode
  // `container.exec({Cmd: cmd})` — the shell-array recognition runs at the
  // *outer* call site below, not here, because `container.exec` is excluded
  // from flat sink classification on purpose (it accepts non-shell argv
  // arrays in the canonical form).
  return "";
}

app.get("/run", async (req: any, res: any) => {
  const name = req.query.name;
  // TP: `name` is interpolated inside a single-quoted shell context.  A
  // quote in `name` escapes the quoting and runs arbitrary shell commands.
  // Detection must fire here, at the call site of the user wrapper, even
  // though the wrapper is opaque to summary inference.
  await runShellWrapper("container-id", [
    "bash",
    "-c",
    `echo 'hello ${name}' > /tmp/out`,
  ]);
  res.send("ok");
});
