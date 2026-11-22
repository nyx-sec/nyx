<?php
// The cast value is a number whether it sits in a variable or a field.
function cast_variable() {
    $n = (int) $_GET['n'];
    unlink($n);
}

function cast_field() {
    $o = new stdClass;
    $o->count = (int) $_GET['n'];
    $o->path = '/tmp/fixed';
    unlink($o->path);
}
