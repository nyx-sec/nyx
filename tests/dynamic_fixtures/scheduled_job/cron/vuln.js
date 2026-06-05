// Phase 21 (Track M.3) — node-cron scheduled-job vuln fixture.
//
// `tick(payload)` is a job registered with `cron.schedule(...)` that
// splices the payload into a child-process command.  An attacker who
// can stage payload bytes into the job's input source can inject
// shell metacharacters.
const _NYX_ADAPTER_MARKER = "require('node-cron')";
const _NYX_SCHEDULE_MARKER = "cron.schedule('*/5 * * * *', tick)";

const { execSync } = require('child_process');

function tick(payload) {
    // SINK: tainted payload concatenated into shell command.
    return execSync('echo ' + String(payload)).toString();
}

module.exports = { tick };
