<?php
function stop_daemon($path)
{
    $pid = (int) trim(file_get_contents($path));
    passthru('kill -9 ' . $pid);
}
