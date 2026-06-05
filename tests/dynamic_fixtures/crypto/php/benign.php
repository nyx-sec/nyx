<?php
// Phase 11 (Track J.9) — PHP CRYPTO benign control fixture.
//
// Uses `random_bytes(32)` (a CSPRNG) for key derivation.
function run($_value) {
    return random_bytes(32);
}
