// Command injection — negative fixture.
// Safe: uses execFile (no shell) with args array; shell metacharacters ignored.
// Entry: runPing(host)  Cap: CODE_EXEC
// Expected verdict: NotConfirmed

const { execFileSync } = require('child_process');

function runPing(host) {
    // execFile does not invoke a shell — semicolons and metacharacters are inert.
    try {
        const out = execFileSync('echo', ['hello', host], { encoding: 'utf8', timeout: 5000 });
        process.stdout.write(out);
    } catch (e) {
        process.stdout.write('error\n');
    }
}

module.exports = { runPing };
