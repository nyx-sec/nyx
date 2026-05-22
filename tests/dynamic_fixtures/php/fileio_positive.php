<?php
// File I/O — positive fixture.
// Vulnerable: reads file at user-controlled path without sanitization.
// Entry: runReadFile($userPath)  Cap: FILE_IO
// Expected verdict: Confirmed (../../../../etc/passwd → "root:" in output)

function runReadFile($userPath) {
    $filePath = '/var/data/' . $userPath;
    echo "__NYX_SINK_HIT__\n";
    $content = @file_get_contents($filePath);
    if ($content !== false) {
        echo $content;
    }
}
