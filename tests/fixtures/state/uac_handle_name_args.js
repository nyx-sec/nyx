const fs = require('fs');

// A closed stream keeps its path.
function describe(p, res) {
  const s = fs.createReadStream(p);
  s.close();
  res.write(s.path);
}
