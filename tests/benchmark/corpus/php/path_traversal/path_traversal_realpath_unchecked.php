<?php
$base = '/srv/files/';
$name = $_GET['f'];
// realpath resolves symlinks and `..` but does not confine the result.
$path = realpath($base . $name);
include($path);
