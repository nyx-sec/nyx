const express = require('express');
const app = express();

// Vulnerable: a literal base does not pin the host. An absolute
// (`https://evil/`) or protocol-relative (`//evil/`) path replaces it.
app.get('/proxy', async (req, res) => {
  const target = new URL(req.query.path, 'https://api.example.com');
  await fetch(target);
  res.end();
});

// Vulnerable: same through a const-bound base.
app.get('/proxy2', async (req, res) => {
  const base = 'https://api.example.com/v1/';
  const target = new URL(req.query.path, base);
  await fetch(target);
  res.end();
});

// Safe: a fixed `/segment` head makes the path an absolute-path reference,
// which keeps the base host whatever follows.
app.get('/items', async (req, res) => {
  const target = new URL('/v1/items/' + req.query.id, 'https://api.example.com');
  await fetch(target);
  res.end();
});

// Safe: template literal with a fixed relative head.
app.get('/users', async (req, res) => {
  const base = 'https://api.example.com';
  const target = new URL(`/v1/users/${req.query.id}`, base);
  await fetch(target);
  res.end();
});

// Vulnerable: `/` followed by user text can still be `//evil/`.
app.get('/loose', async (req, res) => {
  const target = new URL('/' + req.query.path, 'https://api.example.com');
  await fetch(target);
  res.end();
});

// Vulnerable: a bare leading word can complete a scheme (`a` + `://evil`).
app.get('/word', async (req, res) => {
  const target = new URL('v1' + req.query.path, 'https://api.example.com');
  await fetch(target);
  res.end();
});
