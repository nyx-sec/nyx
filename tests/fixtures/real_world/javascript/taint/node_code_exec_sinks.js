const express = require('express');
const vm = require('vm');
const { runInThisContext } = require('node:vm');
const app = express();

app.get('/new-function', (req, res) => {
  const f = new Function('a', req.query.body);
  f(1);
  res.end();
});

app.get('/function-call', (req, res) => {
  const g = Function('return ' + req.query.expr);
  g();
  res.end();
});

app.get('/vm-new-context', (req, res) => {
  vm.runInNewContext(req.query.code, {});
  res.end();
});

app.get('/vm-script', (req, res) => {
  const script = new vm.Script(req.query.code);
  script.runInNewContext({});
  res.end();
});

app.get('/vm-destructured', (req, res) => {
  runInThisContext(req.query.code);
  res.end();
});

// Safe: only the sandbox object carries request data; the compiled source
// is a constant.
app.get('/vm-sandbox', (req, res) => {
  vm.runInNewContext('name.toUpperCase()', { name: req.query.name });
  res.end();
});
