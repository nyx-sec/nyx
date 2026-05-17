<?php
// Phase 03 (Track J.1) — PHP deserialize benign fixture.
//
// Passes `allowed_classes => false` so every object becomes a
// `__PHP_Incomplete_Class` instead of materialising the gadget.
function run(string $blob) {
    return unserialize($blob, ['allowed_classes' => false]);
}
