// The return in the try body runs the finally clause, which closes the fd.
const fs = require('fs');

function readIt(path) {
  const fd = fs.openSync(path, 'r');
  try {
    return fs.readFileSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

module.exports = readIt;
