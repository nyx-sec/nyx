// Command injection — positive fixture.
// Vulnerable: passes user input directly to shell via execSync.
// Entry: runPing(host)  Cap: CODE_EXEC
// Expected verdict: Confirmed ("; echo NYX_PWN_CMDI" payload echoes marker)

const { execSync } = require('child_process');

function runPing(host) {
    process.stdout.write('__NYX_SINK_HIT__\n');
    try {
        const out = execSync('echo hello ' + host, { encoding: 'utf8', timeout: 5000 });
        process.stdout.write(out);
    } catch (e) {
        process.stdout.write((e.stdout || '') + (e.stderr || ''));
    }
}

module.exports = { runPing };
