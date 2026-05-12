// Command injection — unsupported fixture.
// Entry expects a pre-parsed args array, not a string payload.
// Test sets confidence = Low to get Unsupported(ConfidenceTooLow).
// Entry: runCommand(args)  Cap: CODE_EXEC
// Expected verdict: Unsupported

const { execFileSync } = require('child_process');

function runCommand(args) {
    // args is expected to be an array; a string payload can't be routed here.
    if (!Array.isArray(args) || args.length === 0) {
        return;
    }
    execFileSync(args[0], args.slice(1), { encoding: 'utf8', timeout: 5000 });
}

module.exports = { runCommand };
