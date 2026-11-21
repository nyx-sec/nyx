const fs = require('fs');

function readIt(path) {
  const fd = fs.openSync(path, 'r');
  try {
    const data = fs.readFileSync(fd);
    return data;
  } finally {
    console.log('done');
  }
}
