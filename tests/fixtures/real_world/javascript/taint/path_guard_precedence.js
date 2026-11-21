const express = require("express");
const path = require("path");
const app = express();

const ROOT = "/srv/files/";

// Vulnerable: `&&` binds tighter than `||`, so an admin reaches the read
// without the root check.
app.get("/a", (req, res) => {
  const p = path.normalize(req.query.f);
  if ((p.startsWith(ROOT) && req.query.ok) || req.query.admin) {
    res.sendFile(p);
  }
});

// Vulnerable: a one-separator test misses a normalised `..` and `..\x`.
app.get("/b", (req, res) => {
  const c = path.normalize(req.query.f);
  if (path.isAbsolute(c) || c.startsWith("../")) {
    return res.sendStatus(400);
  }
  res.sendFile(path.join(ROOT, c));
});

// Safe: the bare `..` prefix test and the absolute test cover every
// normalised escape.
app.get("/c", (req, res) => {
  const c = path.normalize(req.query.f);
  if (path.isAbsolute(c) || c.startsWith("..")) {
    return res.sendStatus(400);
  }
  res.sendFile(path.join(ROOT, c));
});
