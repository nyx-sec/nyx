<?php
// Command injection — negative fixture.
// Safe: uses escapeshellarg() to prevent shell injection.
// Entry: runPing($host)  Cap: CODE_EXEC
// Expected verdict: NotConfirmed

function runPing($host) {
    // escapeshellarg wraps in single quotes and escapes internal quotes.
    $safe = escapeshellarg($host);
    $output = shell_exec('echo hello ' . $safe);
    if ($output !== null) {
        echo $output;
    }
}
