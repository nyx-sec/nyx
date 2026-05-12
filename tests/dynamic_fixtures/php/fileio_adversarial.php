<?php
// File I/O — adversarial collision fixture.
// Prints "root:" unconditionally without reading any file
// and without emitting __NYX_SINK_HIT__.
// Expected verdict: Inconclusive(OracleCollisionSuspected)
// Entry: readFile($userPath)  Cap: FILE_IO

function readFile($userPath) {
    // Coincidental oracle match — not a file read sink.
    echo "root: present\n";
    $x = strlen($userPath);
}
