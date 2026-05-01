// Wrapper around `fetch` whose two parameters target distinct gated-sink
// classes on the inner call: `url` is the SSRF gate's destination; `body`
// is the DATA_EXFIL gate's payload. Pass-1 SSA summary extraction lifts
// the per-position cap split into `param_to_gate_filters` so cross-file
// callers can attribute SSRF vs DATA_EXFIL per argument.
function forward(url, body) {
    fetch(url, { method: 'POST', body: body });
}

module.exports = { forward };
