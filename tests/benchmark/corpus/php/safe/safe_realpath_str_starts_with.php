<?php
$base = '/srv/files/';
$name = $_GET['f'];
$path = realpath($base . $name);
if ($path === false || !str_starts_with($path, $base)) {
    die('forbidden');
}
include($path);
