const { execSync } = require('child_process');

function deploy(payload) {
  return execSync('deploy ' + payload);
}

function status(input) {
  return execSync('status ' + input);
}

module.exports = { deploy, status };
