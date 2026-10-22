<?php
// The only request value appended with `.=` is escaped first.
$out = "<p>";
$out .= htmlspecialchars($_GET['bio']);
$out .= "</p>";
echo $out;
