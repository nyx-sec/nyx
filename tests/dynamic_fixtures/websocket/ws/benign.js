// Phase 21 — `ws` WebSocket benign control.
const _NYX_ADAPTER_MARKER = "require('ws')";
const _NYX_WS_MESSAGE_MARKER = "wss.on('connection', ws => ws.on('message', onMessage))";

function onMessage(data) {
    return 'echoed: ' + JSON.stringify(String(data));
}

module.exports = { onMessage };
