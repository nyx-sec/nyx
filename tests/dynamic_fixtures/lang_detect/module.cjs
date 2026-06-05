// CommonJS module — `.cjs` extension. Identifies as JavaScript.
const { exec } = require("child_process");

function runCommand(payload) {
    exec("ls " + payload);
}

module.exports = { runCommand };
