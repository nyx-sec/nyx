// File I/O — unsupported fixture.
// Entry takes a Buffer (binary), not a UTF-8 string payload.
// Test sets confidence = Low to get Unsupported(ConfidenceTooLow).
// Entry: processUpload(buf)  Cap: FILE_IO
// Expected verdict: Unsupported

const fs = require('fs');

function processUpload(buf) {
    if (!Buffer.isBuffer(buf)) {
        return;
    }
    const tmpPath = '/tmp/upload_' + Date.now();
    fs.writeFileSync(tmpPath, buf);
    const content = fs.readFileSync(tmpPath, 'utf8');
    process.stdout.write(content.substring(0, 64));
    fs.unlinkSync(tmpPath);
}

module.exports = { processUpload };
