// Containment by string prefix: the root must end with a separator, or a
// sibling such as /srv/files-backup passes the test.
const path = require("path");
const express = require("express");
const app = express();

// path.resolve drops any trailing separator.
const BARE_ROOT = path.resolve("/srv/files");
const DIR_ROOT = path.resolve("/srv/files") + path.sep;

app.get("/bare-const", (req, res) => {
  const p = path.resolve(req.query.f);
  if (!p.startsWith(BARE_ROOT)) {
    return res.sendStatus(403);
  }
  res.sendFile(p); // @vuln sibling directory shares the prefix
});

app.get("/bare-literal", (req, res) => {
  const p = path.resolve(req.query.f);
  if (!p.startsWith("/srv/files")) {
    return res.sendStatus(403);
  }
  res.sendFile(p); // @vuln sibling directory shares the prefix
});

app.get("/short-literal", (req, res) => {
  const p = path.resolve(req.query.f);
  if (!p.startsWith("/s")) {
    return res.sendStatus(403);
  }
  res.sendFile(p); // @vuln admits every top level directory starting with s
});

app.get("/dir-literal", (req, res) => {
  const p = path.resolve(req.query.f);
  if (!p.startsWith("/srv/files/")) {
    return res.sendStatus(403);
  }
  res.sendFile(p); // @safe root ends with a separator
});

app.get("/dir-const", (req, res) => {
  const p = path.resolve(req.query.f);
  if (!p.startsWith(DIR_ROOT)) {
    return res.sendStatus(403);
  }
  res.sendFile(p); // @safe constant ends with a separator
});

app.get("/sep-joined", (req, res) => {
  const p = path.resolve(req.query.f);
  if (!p.startsWith(BARE_ROOT + path.sep)) {
    return res.sendStatus(403);
  }
  res.sendFile(p); // @safe separator appended at the test
});

app.get("/sep-joined-literal", (req, res) => {
  const p = path.resolve(req.query.f);
  if (!p.startsWith(BARE_ROOT + "/")) {
    return res.sendStatus(403);
  }
  res.sendFile(p); // @safe separator appended at the test
});
