const fs = require('fs');

function leakyWrite(dst, data) {
  const out = fs.createWriteStream(dst);
  out.write(data);
}

// pipe() leaves the destination open when the source errors.
function leakyPipe(src, dst) {
  const out = fs.createWriteStream(dst);
  src.pipe(out);
}

class Holder {
  open(p) {
    this.fd = fs.openSync(p, 'r');
  }
}
