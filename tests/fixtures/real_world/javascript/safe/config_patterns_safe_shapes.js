const nodemailer = require('nodemailer');
const session = require('express-session');

const ALLOWED = ['https://app.example.com', 'https://admin.example.com'];

// Safe: only an allowlisted origin is echoed.
function corsAllowlisted(req, res) {
  const origin = req.headers.origin;
  if (ALLOWED.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
}

// Safe: early exit on a non-allowlisted origin.
function corsEarlyExit(req, res) {
  const origin = req.headers.origin;
  if (!ALLOWED.includes(origin)) return res.status(403).end();
  res.setHeader('Access-Control-Allow-Origin', origin);
}

// Safe: `secure: false` on a mail transport is STARTTLS, not a cookie.
const mail = nodemailer.createTransport({ host: 'smtp.example.com', port: 587, secure: false });

// Safe: constants written to location and document.cookie.
function constants() {
  window.location = '/home';
  document.cookie = 'theme=dark; path=/';
}

// Safe: `error` is a message string the handler wrote itself.
function login(req, res) {
  const error = 'Invalid credentials';
  res.render('login', { error });
}

// Vulnerable twins, one per pattern.
function corsReflected(req, res) {
  const origin = req.headers.origin;
  res.setHeader('Access-Control-Allow-Origin', origin);
}

const store = session({ secret: process.env.SESSION_SECRET, cookie: { secure: false } });

function redirectTo(url, sid) {
  window.location = url;
  document.cookie = 'sid=' + sid;
}

function fail(req, res, err) {
  const error = err;
  res.render('error', { error });
}
