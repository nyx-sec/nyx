// Phase 13 — browser-side event handler, benign control.
//
// Uses `textContent` so the payload's `<script>` tag is HTML-escaped before
// serialisation; the XSS oracle marker cannot appear in stdout because
// `<` becomes `&lt;`.

'use strict';
// nyx-shape: browser-event

function clickHandler(payload) {
    process.stdout.write('__NYX_SINK_HIT__\n');
    const el = document.getElementById('out');
    if (el) {
        el.textContent = String(payload);
    }
    return el ? el.textContent : '';
}

module.exports = { clickHandler };
