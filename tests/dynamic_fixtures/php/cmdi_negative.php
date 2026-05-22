<?php
// Command injection — negative fixture.
// Safe: uses escapeshellarg() and discards the captured output.
// Entry: runPing($host)  Cap: CODE_EXEC
// Expected verdict: NotConfirmed
//
// Pairs with cmdi_positive.php for differential confirmation. The
// captured output is intentionally discarded so a literal payload such
// as "; echo NYX_PWN_CMDI" (which escapeshellarg already neutralises
// against the shell parser) cannot leak through stdout and trip the
// OutputContains oracle.

function runPing($host) {
    // Sink-reachability probe: we did reach the shell_exec call site.
    echo "__NYX_SINK_HIT__\n";
    // escapeshellarg wraps in single quotes and escapes internal quotes.
    $safe = escapeshellarg($host);
    // Capture but discard: command runs under the sanitiser, output is
    // not surfaced to the oracle.
    $output = shell_exec('echo hello ' . $safe);
    unset($output);
}
