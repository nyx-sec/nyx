// File I/O — negative fixture.
// Safe: path is normalized and validated against an allowlist prefix.
// Entry: readFile(userPath)  Cap: FILE_IO
// Expected verdict: NotConfirmed

const fs = require('fs');
const path = require('path');

const BASE_DIR = '/var/data';

function readFile(userPath) {
    const resolved = path.resolve(BASE_DIR, userPath);
    if (!resolved.startsWith(BASE_DIR + path.sep) && resolved !== BASE_DIR) {
        process.stdout.write('Access denied\n');
        return;
    }
    try {
        const content = fs.readFileSync(resolved, 'utf8');
        process.stdout.write(content.substring(0, 100));
    } catch (e) {
        process.stdout.write('File not found\n');
    }
}

module.exports = { readFile };
