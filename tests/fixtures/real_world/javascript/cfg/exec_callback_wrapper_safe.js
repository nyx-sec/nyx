const { exec } = require("child_process");

function execAsync(cmd) {
  return new Promise((resolve, reject) => {
    exec(cmd, (error, stdout) => {
      if (error) reject(error);
      else resolve(stdout);
    });
  });
}

function done() {}

function runNamed(cmd) {
  exec(cmd, done);
}

function runLogged(cmd) {
  exec(cmd, (error, stdout) => {
    console.log(stdout);
  });
}

execAsync("rm -rf ./build/server");
runNamed("ls");
runLogged("ls");
