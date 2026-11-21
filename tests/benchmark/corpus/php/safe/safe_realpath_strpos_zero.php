<?php
$base = '/srv/files/';
$name = $_GET['f'];
$path = realpath($base . $name);
if ($path === false || strpos($path, $base) !== 0) {
    die('forbidden');
}
include($path);
