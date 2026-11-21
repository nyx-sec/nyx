const fs = require('fs');

// Expected: no resource findings.
function strictNull(p) {
  const fd = fs.openSync(p, 'r');
  if (fd === null) {
    return -1;
  }
  fs.closeSync(fd);
  return 0;
}

function notFd(p) {
  const fd = fs.openSync(p, 'r');
  if (!fd) {
    return -1;
  }
  fs.closeSync(fd);
  return 0;
}
