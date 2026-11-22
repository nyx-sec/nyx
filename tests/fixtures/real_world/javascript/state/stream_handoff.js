const fs = require('fs');
const { pipeline } = require('stream');

// pipeline() destroys every stream on error or completion.
function copyPipeline(src, dst, cb) {
  const out = fs.createWriteStream(dst);
  pipeline(src, out, cb);
}

// The caller's context owns the stream once it is stored on it.
module.exports = (ctx) => {
  ctx.body = fs.createReadStream('/tmp/index.html');
};

// Used locally and never closed.
function leaky(dst, data) {
  const out = fs.createWriteStream(dst);
  out.write(data);
}

class Holder {
  open(p) {
    this.fd = fs.openSync(p, 'r');
  }
}

// The factory returns the stream; the caller owns it.
function mk(file) {
  const getStream = () => fs.createReadStream(file.filepath);
  return { getStream };
}
