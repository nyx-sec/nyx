// A prefix test compared against a boolean sentinel: the lock belongs to the
// edge where the test is true, however the comparison is spelled.
const path = require("path");
const express = require("express");
const app = express();

const ROOT = "/srv/files/";

app.get("/eq-false-reject", (req, res) => {
  const p = path.resolve(req.query.f);
  if (p.startsWith(ROOT) === false) {
    return res.sendStatus(403);
  }
  res.sendFile(p); // @safe reached only when the prefix test is true
});

app.get("/loose-eq-false-reject", (req, res) => {
  const p = path.resolve(req.query.f);
  if (p.startsWith(ROOT) == false) {
    return res.sendStatus(403);
  }
  res.sendFile(p); // @safe reached only when the prefix test is true
});

app.get("/ne-true-reject", (req, res) => {
  const p = path.resolve(req.query.f);
  if (p.startsWith(ROOT) !== true) {
    return res.sendStatus(403);
  }
  res.sendFile(p); // @safe reached only when the prefix test is true
});

app.get("/yoda-reject", (req, res) => {
  const p = path.resolve(req.query.f);
  if (false === p.startsWith(ROOT)) {
    return res.sendStatus(403);
  }
  res.sendFile(p); // @safe reached only when the prefix test is true
});

app.get("/double-not", (req, res) => {
  const p = path.resolve(req.query.f);
  if (!!p.startsWith(ROOT)) {
    res.sendFile(p); // @safe inside the prefix test's true edge
  }
});

app.get("/eq-true-serve", (req, res) => {
  const p = path.resolve(req.query.f);
  if (p.startsWith(ROOT) === true) {
    res.sendFile(p); // @safe inside the prefix test's true edge
  }
});

app.get("/eq-false-serve", (req, res) => {
  const p = path.resolve(req.query.f);
  if (p.startsWith(ROOT) === false) {
    res.sendFile(p); // @vuln the path is outside the root here
  }
});

app.get("/ne-true-serve", (req, res) => {
  const p = path.resolve(req.query.f);
  if (p.startsWith(ROOT) !== true) {
    res.sendFile(p); // @vuln the path is outside the root here
  }
});

app.get("/yoda-serve", (req, res) => {
  const p = path.resolve(req.query.f);
  if (false === p.startsWith(ROOT)) {
    res.sendFile(p); // @vuln the path is outside the root here
  }
});

app.get("/unknown-sentinel", (req, res) => {
  const p = path.resolve(req.query.f);
  if (p.startsWith(ROOT) === 0) {
    return res.sendStatus(403);
  }
  res.sendFile(p); // @vuln the comparison proves nothing about the root
});
