// Phase 13 — browser-side event handler, vulnerable.
//
// Harness spins up jsdom (js_shared::emit_browser_event), assigns
// `globalThis.document`, then calls `clickHandler(payload)`.  The handler
// writes payload into innerHTML — the XSS oracle's `<script>NYX_XSS_CONFIRMED
// </script>` payload appears in the serialised DOM the harness mirrors to
// stdout.

'use strict';
// nyx-shape: browser-event

function clickHandler(payload) {
    process.stdout.write('__NYX_SINK_HIT__\n');
    const el = document.getElementById('out');
    if (el) {
        el.innerHTML = String(payload);
    }
    return el ? el.innerHTML : '';
}

module.exports = { clickHandler };
