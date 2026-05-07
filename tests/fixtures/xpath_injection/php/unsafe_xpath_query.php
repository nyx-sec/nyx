<?php
// Unsafe: $_GET['user'] concatenated into an XPath expression and passed
// straight to SimpleXMLElement::xpath.  XPATH_INJECTION fires on the
// expression argument.
$xml = simplexml_load_file("users.xml");
$user = $_GET['user'];
$expr = "//user[name='" . $user . "']";
$nodes = $xml->xpath($expr);
