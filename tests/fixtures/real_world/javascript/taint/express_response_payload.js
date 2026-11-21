const express = require('express');
const app = express();

// Fluent chains send through the final method.
app.get('/status-send', (req, res) => {
  const q = req.query.q;
  res.status(200).send('<p>' + q + '</p>');
});

app.get('/status-redirect', (req, res) => {
  res.status(302).redirect(req.query.next);
});

app.get('/set-send', (req, res) => {
  const q = req.query.q;
  res.set('Content-Type', 'text/html').send(q);
});

// Safe: request data reaches the response object, never the written body.
app.use((req, res, next) => {
  res.locals.search = req.query.q;
  res.json({ ok: true });
});

app.get('/locals-redirect', (req, res) => {
  res.locals.user = req.body.user;
  res.redirect('/home');
});

async function loadItem(id) {
  const res = await fetch('/api/items/' + id);
  return res.json();
}

app.get('/item', async (req, res) => {
  const item = await loadItem(req.query.id);
  res.status(item ? 200 : 404).json();
});
