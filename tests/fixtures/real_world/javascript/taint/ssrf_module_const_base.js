const express = require('express');
const axios = require('axios');
const app = express();

const API = 'https://api.example.com/';

// Safe: module-level constant host, concatenation in the argument.
app.get('/a', async (req, res) => {
  const r = await axios.get(API + req.query.p);
  res.end();
});

// Safe: template literal that opens with the constant.
app.get('/b', async (req, res) => {
  const r = await axios.get(`${API}users/${req.query.p}`);
  res.end();
});

// Safe: through an assignment.
app.get('/c', async (req, res) => {
  const url = `${API}users/${req.query.p}`;
  const r = await axios.get(url);
  res.end();
});

// Safe: left-nested concatenation with a literal head.
app.get('/d', async (req, res) => {
  const r = await axios.get('https://api.example.com/items/' + req.query.id + '/details');
  res.end();
});

// Vulnerable: the whole URL.
app.get('/e', async (req, res) => {
  const r = await axios.get(req.query.u);
  res.end();
});

// Vulnerable: the name is rebound by a parameter, so the constant does not apply.
app.get('/f', async (req, res) => {
  const r = await build(req.query.u);
  res.end();
});
function build(API) {
  return axios.get(API + '/x');
}

// Vulnerable: a helper returns its argument on one path and a locked URL on the other.
function helper(p, raw) {
  if (raw) {
    return p;
  }
  return 'https://api.example.com/' + p;
}
app.get('/g', async (req, res) => {
  const u = helper(req.query.u, req.headers['x-raw']);
  const r = await axios.get(u);
  res.end();
});
