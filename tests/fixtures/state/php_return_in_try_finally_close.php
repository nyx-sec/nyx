<?php
function readIt($path) {
    $h = fopen($path, "r");
    try {
        return fread($h, 10);
    } finally {
        fclose($h);
    }
}
