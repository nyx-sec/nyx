const { exec } = require("child_process");

// `dryRun` is the constant false, so the else branch runs; `quiet` is the
// constant true, so `!quiet` never holds.
function run() {
  const cmd = process.env.USER_COMMAND;
  const dryRun = false;
  if (dryRun) {
    return;
  } else {
    exec(cmd);
  }
  const quiet = true;
  if (!quiet) {
    exec("echo " + cmd);
  }
}

run();
