// Phase 21 — node-cron benign control.
const _NYX_ADAPTER_MARKER = "require('node-cron')";
const _NYX_SCHEDULE_MARKER = "cron.schedule('*/5 * * * *', tick)";

function tick(payload) {
    return 'tick: ' + JSON.stringify(payload);
}

module.exports = { tick };
