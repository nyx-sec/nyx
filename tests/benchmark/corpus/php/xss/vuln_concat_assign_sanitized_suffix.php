<?php
// Only the appended part is escaped.  The raw name already in `$out`
// still reaches echo.
$out = "<h1>" . $_GET['name'] . "</h1>";
$out .= htmlspecialchars($_GET['bio']);
echo $out;
