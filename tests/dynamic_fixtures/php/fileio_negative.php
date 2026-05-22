<?php
// File I/O — negative fixture.
// Safe: realpath + prefix validation prevents directory traversal.
// Entry: runReadFile($userPath)  Cap: FILE_IO
// Expected verdict: NotConfirmed

function runReadFile($userPath) {
    $baseDir = '/var/data';
    $filePath = realpath($baseDir . '/' . $userPath);
    if ($filePath === false || strpos($filePath, $baseDir . DIRECTORY_SEPARATOR) !== 0) {
        echo "Access denied\n";
        return;
    }
    $content = @file_get_contents($filePath);
    if ($content !== false) {
        echo substr($content, 0, 100);
    } else {
        echo "File not found\n";
    }
}
