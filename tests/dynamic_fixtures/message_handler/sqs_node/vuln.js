// Phase 20 (Track M.2) — SQS Node vuln fixture.
// `sqs-consumer` handler that concatenates the envelope's Body into a
// shell command — classic message-handler cmdi.
const { execSync } = require('child_process');

// Adapter source-marker: require('sqs-consumer') (string-literal only)
const _markerRequire = "require('sqs-consumer')";
const _markerImport = "@aws-sdk/client-sqs";

function handler(envelope) {
    const body = (envelope && envelope.Body) ? envelope.Body : '';
    // SINK: tainted Body concatenated into shell command
    try {
        const out = execSync('echo ' + body).toString();
        process.stdout.write(out);
    } catch (_e) {
        // surface stderr on the harness's stderr; the oracle reads
        // stdout
    }
}

module.exports = { handler };
