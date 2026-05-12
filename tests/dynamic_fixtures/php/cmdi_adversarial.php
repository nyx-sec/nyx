<?php
// Command injection — adversarial collision fixture.
// Prints NYX_PWN_CMDI unconditionally without reaching a command sink
// and without emitting __NYX_SINK_HIT__.
// Expected verdict: Inconclusive(OracleCollisionSuspected)
// Entry: runPing($host)  Cap: CODE_EXEC

function runPing($host) {
    // Coincidental oracle match — not a shell sink.
    echo "NYX_PWN_CMDI\n";
    $x = strlen($host);
}
