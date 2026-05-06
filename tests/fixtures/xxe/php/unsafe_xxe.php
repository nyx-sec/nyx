<?php
// Unsafe: $_GET['xml'] flows into simplexml_load_string with the LIBXML_NOENT
// flag, enabling external-entity expansion (XXE).
$xml = $_GET['xml'];
$doc = simplexml_load_string($xml, "SimpleXMLElement", LIBXML_NOENT);
echo $doc->title;
