<?php
// Safe: $_GET['user'] routed through the project-local `escape_xpath` helper
// before concatenation.  The sanitizer clears XPATH_INJECTION so the sink
// does not fire.
function escape_xpath($raw) {
    return str_replace(["'", "\""], ["&apos;", "&quot;"], $raw);
}

$xml = simplexml_load_file("users.xml");
$user = $_GET['user'];
$safe = escape_xpath($user);
$expr = "//user[name='" . $safe . "']";
$nodes = $xml->xpath($expr);
