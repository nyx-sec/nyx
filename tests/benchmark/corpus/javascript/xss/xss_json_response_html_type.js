const Koa = require('koa');
const express = require('express');

const app = new Koa();
const web = express();

// An HTML content type makes the body render as markup, so these stay sinks.
app.use(async (ctx) => {
  ctx.type = 'html';
  ctx.body = { a: ctx.query.x };
});

web.get('/a', (req, res) => {
  res.type('html');
  res.json(req.query.x);
});

web.get('/b', (req, res) => {
  res.contentType('text/html');
  res.json(req.query.x);
});

module.exports = { app, web };
