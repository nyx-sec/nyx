<?php
// Command injection — positive fixture.
// Vulnerable: passes user input directly to shell_exec.
// Entry: runPing($host)  Cap: CODE_EXEC
// Expected verdict: Confirmed ("; echo NYX_PWN_CMDI" echoes the marker)

function runPing($host) {
    echo "__NYX_SINK_HIT__\n";
    $output = shell_exec('echo hello ' . $host);
    if ($output !== null) {
        echo $output;
    }
}
