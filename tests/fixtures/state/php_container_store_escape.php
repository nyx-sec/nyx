<?php
// Expected: no resource findings.
function collect($p, &$handles) {
    $f = fopen($p, "r");
    array_push($handles, $f);
}

function collect_append($p, &$handles) {
    $f = fopen($p, "r");
    $handles[] = $f;
}
