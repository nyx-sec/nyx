const fs = require('fs');
const { pipeline } = require('stream');

function copyPipeline(src, dst, cb) {
  const out = fs.createWriteStream(dst);
  pipeline(src, out, cb);
}

module.exports = (ctx) => {
  ctx.body = fs.createReadStream('/tmp/index.html');
};

function makeFactory(file) {
  const getStream = () => fs.createReadStream(file.filepath);
  return { getStream };
}

async function nested(rq, p) {
  const res = await rq({ formData: { files: fs.createReadStream(p) } });
  return res.statusCode;
}
