<?php
$base = '/srv/files/';

// Vulnerable: realpath resolves symlinks but does not confine the path.
function v_realpath() {
    global $base;
    $f = $_GET['f'];
    $p = realpath($base . $f);
    include($p);
}

// Safe: realpath, then a prefix check against the base.
function s_realpath_str_starts_with() {
    global $base;
    $f = $_GET['f'];
    $p = realpath($base . $f);
    if ($p === false || !str_starts_with($p, $base)) {
        die('no');
    }
    include($p);
}

// Safe: the same with the strpos spelling.
function s_realpath_strpos() {
    global $base;
    $f = $_GET['f'];
    $p = realpath($base . $f);
    if ($p === false || strpos($p, $base) !== 0) {
        die('no');
    }
    include($p);
}

// Safe: basename keeps only the final component.
function s_basename() {
    global $base;
    $n = basename($_GET['f']);
    include($base . $n);
}

// Vulnerable: a loose `!= 0` lets a path outside the base through, since
// `strpos` returns `false` there and `false != 0` is false.
function v_realpath_strpos_loose() {
    global $base;
    $f = $_GET['f'];
    $p = realpath($base . $f);
    if (strpos($p, $base) != 0) {
        die('no');
    }
    include($p);
}
