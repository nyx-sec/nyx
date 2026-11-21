<?php
// The request value is quoted with escapeshellarg inside the command string.
$file = $_GET['file'];
$out = shell_exec('wc -l ' . escapeshellarg($file));
echo htmlspecialchars($out);
