<?php
// PHP JSON_PARSE depth-bomb vuln fixture.
//
// Models a config-driven JSON ingest endpoint that picks the parser
// input based on the request payload tag - `*_DEEP` routes through a
// deeply-nested array literal (256 levels) that drives `json_decode`
// past the 64-level depth budget; `*_SHALLOW` routes through a flat
// `[]` parse that leaves the predicate clear.  This shape is needed by
// the differential runner: the vuln-payload attempt and the
// benign-control attempt both load the same fixture, and only the
// payload-routed deep branch trips the `JsonParseExcessiveDepth`
// predicate.
//
// PHP cannot monkey-patch `json_decode` itself.  The harness publishes
// a global `_nyx_json_decode($s)` helper that proxies the real
// `json_decode` and records the parse depth before returning.  Inside
// the synthetic `Nyx\Captured` namespace the harness eval's this
// fixture into, PHP's unqualified function-call resolution falls back
// to the global namespace, so the call site below routes through the
// harness helper at runtime.  When this fixture runs standalone (no
// harness) the fallback definition near the bottom of the file kicks
// in and the helper degrades to a direct `json_decode` call.

function run($value) {
    $text = is_string($value) ? $value : (string) json_encode($value);
    if (strpos($text, 'DEEP') !== false) {
        $nested = str_repeat('[', 256) . str_repeat(']', 256);
        return _nyx_json_decode($nested);
    }
    return _nyx_json_decode('[]');
}

if (!function_exists('_nyx_json_decode')) {
    function _nyx_json_decode($s) {
        return json_decode($s, true, 4096);
    }
}
