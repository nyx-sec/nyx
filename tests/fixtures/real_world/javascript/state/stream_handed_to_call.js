const fs = require('fs');
const path = require('path');
const rq = require('./rq');

describe('upload', () => {
  test('rejects a big file', async () => {
    const res = await rq({
      method: 'POST',
      url: '/upload',
      formData: { files: fs.createReadStream(path.join(__dirname, 'a.png')) },
    });
    expect(res.statusCode).toBe(413);
  });
});

async function sendWrapped(p) {
  const result = await rq({ body: fs.createReadStream(p) });
  return result.statusCode;
}

async function leaksStream(p) {
  const s = fs.createReadStream(p);
  s.on('data', (d) => console.log(d.length));
}
