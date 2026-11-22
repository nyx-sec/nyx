// js-path-traversal-startswith-eq-false: the sink sits inside the branch where
// the prefix test is false, so the path is outside the root.  Comparing the
// test against false must not be read as a containment check.
const fs = require("fs");
const path = require("path");

const ROOT = "/srv/files/";

function serve(req, res) {
  const name = req.query.name;
  const target = path.resolve(path.join(ROOT, name));
  if (target.startsWith(ROOT) === false) {
    fs.readFile(target, (err, data) => res.send(data));
  }
}

module.exports = { serve };
