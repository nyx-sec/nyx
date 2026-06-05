<?php
// Phase 11 (Track J.9) — PHP CRYPTO vuln fixture.
//
// Models a config-driven crypto endpoint that picks the RNG based on
// the request payload — `*_WEAK` routes through `mt_rand(0, 0xFFFF)`
// (a non-CSPRNG) and `*_STRONG` routes through `random_bytes(32)`
// (a CSPRNG).  This shape is needed by the differential runner: the
// vuln-payload attempt and the benign-control attempt both load the
// same fixture, and only the payload-routed weak branch trips the
// `WeakKeyEntropy` predicate.
function run($value) {
    $s = is_string($value) ? $value : strval($value);
    if (strpos($s, "STRONG") !== false) {
        return random_bytes(32);
    }
    return mt_rand(0, 0xFFFF);
}
