const fs = require('fs');

// Expected: no resource findings.
function track(p, list) {
  const fd = fs.openSync(p, 'r');
  list.push(fd);
}

function remember(p, cache) {
  const fd = fs.openSync(p, 'r');
  cache.set(p, fd);
}
