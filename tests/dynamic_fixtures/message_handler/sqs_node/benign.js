// Phase 20 (Track M.2) — SQS Node benign control.
const { execFileSync } = require('child_process');

const _markerRequire = "require('sqs-consumer')";
const _markerImport = "@aws-sdk/client-sqs";

function handler(envelope) {
    const body = (envelope && envelope.Body) ? envelope.Body : '';
    try {
        const out = execFileSync('echo', [body]).toString();
        process.stdout.write(out);
    } catch (_e) {
    }
}

module.exports = { handler };
