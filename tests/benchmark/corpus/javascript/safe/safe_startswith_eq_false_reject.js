// js-safe-startswith-eq-false-reject: rejecting on `startsWith(ROOT) === false`
// leaves only paths inside the root for the sink.
const fs = require("fs");
const path = require("path");

const ROOT = "/srv/files/";

function serve(req, res) {
  const name = req.query.name;
  const target = path.resolve(path.join(ROOT, name));
  if (target.startsWith(ROOT) === false) {
    res.status(403).end();
    return;
  }
  fs.readFile(target, (err, data) => res.send(data));
}

module.exports = { serve };
