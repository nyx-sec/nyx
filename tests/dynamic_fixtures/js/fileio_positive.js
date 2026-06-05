// File I/O — positive fixture.
// Vulnerable: reads a file at a user-controlled path without sanitization.
// Entry: readFile(userPath)  Cap: FILE_IO
// Expected verdict: Confirmed (../../../../etc/passwd → "root:" in output)

const fs = require('fs');
const path = require('path');

function readFile(userPath) {
    const filePath = path.join('/var/data', userPath);
    process.stdout.write('__NYX_SINK_HIT__\n');
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        process.stdout.write(content);
    } catch (e) {
        // Silent on error — target file may not exist in all envs
    }
}

module.exports = { readFile };
