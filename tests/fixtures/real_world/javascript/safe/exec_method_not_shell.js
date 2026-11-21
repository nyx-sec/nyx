const express = require('express');
const { fork } = require('redux-saga/effects');
const User = require('./models/user');
const db = require('./db');
const app = express();

const SEMVER = /^(\d+)\.(\d+)\.(\d+)$/;

app.get('/range', (req, res) => {
  const re = /^(\d+)-(\d+)$/;
  const m = re.exec(req.query.range);
  const v = SEMVER.exec(String(req.query.v));
  res.status(m && v ? 200 : 400).end();
});

app.use((req, res, next) => {
  const auth = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  if (!auth) return res.status(401).end();
  req.token = auth[1];
  next();
});

app.get('/user', async (req, res) => {
  const u = await User.findOne({ name: req.query.name }).exec();
  const q = User.find({ name: req.query.name });
  const docs = await q.exec();
  res.status(u && docs ? 200 : 404).end();
});

function* rootSaga(action) {
  yield fork(action.payload);
}

function parseCookies(header) {
  const out = {};
  const re = /([^=;\s]+)=([^;]*)/g;
  let m;
  while ((m = re.exec(header)) !== null) {
    out[m[1]] = decodeURIComponent(m[2]);
  }
  return out;
}

app.get('/cookies', (req, res) => {
  req.cookiesParsed = parseCookies(req.headers.cookie || '');
  res.end();
});

// Real shell sink alongside the regex calls: must still fire.
app.get('/run', (req, res) => {
  const { exec } = require('child_process');
  exec('ls ' + req.query.dir);
  res.end();
});

module.exports = { app, db, rootSaga };
