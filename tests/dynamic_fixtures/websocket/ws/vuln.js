// Phase 21 (Track M.3) — `ws` WebSocket handler vuln fixture.
//
// `onMessage(data)` is the `on('message', ...)` listener on a
// WebSocketServer instance.  It splices the message bytes into a
// child-process command — classic WS → cmdi shape.
const _NYX_ADAPTER_MARKER = "require('ws')";

const { execSync } = require('child_process');

function onMessage(data) {
    // SINK: tainted message body concatenated into shell command.
    return execSync('echo ' + String(data)).toString();
}

module.exports = { onMessage };
