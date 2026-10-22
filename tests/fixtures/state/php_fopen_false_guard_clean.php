<?php
// fopen returns false on failure.  Expected: no resource findings.

function strict_false($p) {
    $fh = fopen($p, "r");
    if ($fh === false) {
        return null;
    }
    $d = fread($fh, 100);
    fclose($fh);
    return $d;
}

function not_handle($p) {
    $fh = fopen($p, "r");
    if (!$fh) {
        return null;
    }
    $d = fread($fh, 100);
    fclose($fh);
    return $d;
}
