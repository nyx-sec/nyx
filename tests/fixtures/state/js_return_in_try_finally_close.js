const fs = require('fs');

function readIt(path) {
  const fd = fs.openSync(path, 'r');
  try {
    return fs.readFileSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}
