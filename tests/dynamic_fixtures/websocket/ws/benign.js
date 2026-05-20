// Phase 21 — `ws` WebSocket benign control.
const _NYX_ADAPTER_MARKER = "require('ws')";

function onMessage(data) {
    return 'echoed: ' + JSON.stringify(String(data));
}

module.exports = { onMessage };
