<?php
// Phase 11 (Track J.9) — PHP UNAUTHORIZED_ID vuln fixture.
const CALLER_ID = "alice";
$STORE = ["alice" => "alice@x", "bob" => "bob@x"];

function run($ownerId) {
    global $STORE;
    return $STORE[$ownerId] ?? null;
}
