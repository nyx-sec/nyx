// Command injection — negative fixture.
// Safe: uses execFile (no shell) with args array; shell metacharacters ignored.
// Entry: runPing(host)  Cap: CODE_EXEC
// Expected verdict: NotConfirmed
//
// The host string is handed to `true` so it can never appear on stdout (which
// would let an oracle scanning for the vuln-payload marker fire even though
// no command was executed by a shell).  Sub-process stderr is silenced with
// `stdio: 'ignore'` so the same logic holds for `outcome.stderr` — Node's
// default of inheriting child stderr to the parent stream lets `execFile`
// error messages leak the host string otherwise.

const { execFileSync } = require('child_process');

function runPing(host) {
    // Sink-reachability probe: we did reach the execFile call site.
    process.stdout.write('__NYX_SINK_HIT__\n');
    // execFile does not invoke a shell — semicolons and metacharacters are inert.
    try {
        const out = execFileSync('true', [host], {
            encoding: 'utf8',
            timeout: 5000,
            stdio: ['ignore', 'pipe', 'ignore'],
        });
        process.stdout.write(out);
    } catch (e) {
        // true exits 0 with no output; the catch is defensive.
    }
}

module.exports = { runPing };
