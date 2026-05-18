<?php
// Phase 11 (Track J.9) — PHP UNAUTHORIZED_ID benign control fixture.
const CALLER_ID = "alice";
$STORE = ["alice" => "alice@x", "bob" => "bob@x"];

function run($ownerId) {
    global $STORE;
    if ($ownerId !== CALLER_ID) return null;
    return $STORE[$ownerId] ?? null;
}
