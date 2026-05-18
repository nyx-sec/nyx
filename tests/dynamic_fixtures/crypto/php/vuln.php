<?php
// Phase 11 (Track J.9) — PHP CRYPTO vuln fixture.
//
// Uses `mt_rand(0, 0xFFFF)` (a non-CSPRNG) to derive a 16-bit key.
function run($_value) {
    return mt_rand(0, 0xFFFF);
}
