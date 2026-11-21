const { execSync } = require('child_process');
const fs = require('fs');
const express = require('express');
const app = express();

function run(cmd) {
  return execSync(cmd, { stdio: 'inherit' });
}

function readInput(input) {
  return fs.readFileSync(input, 'utf8');
}

function deploy(payload) {
  return execSync('deploy ' + payload);
}

run('npm run build');
run('npm test');
const cfg = JSON.parse(readInput('./config.json'));
console.log(cfg);

app.post('/deploy', (req, res) => {
  deploy(req.body.target);
  res.send('ok');
});

module.exports = function exported(userCommand) {
  return execSync(userCommand);
};
