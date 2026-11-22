const Koa = require('koa');
const express = require('express');

const app = new Koa();
const web = express();

// An explicit JSON content type keeps these responses non-renderable.
app.use(async (ctx) => {
  ctx.type = 'json';
  ctx.body = { a: ctx.query.x };
});

web.get('/a', (req, res) => {
  res.type('json');
  res.json(req.query.x);
});

web.get('/b', (req, res) => {
  res.contentType('application/json');
  res.json(req.query.x);
});

module.exports = { app, web };
