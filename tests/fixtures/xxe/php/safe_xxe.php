<?php
// Safe: simplexml_load_string is XXE-safe by default in libxml ≥ 2.9 when
// the dangerous LIBXML_NOENT flag is not passed.  The gate's `dangerous_values`
// list is restricted to LIBXML_NOENT / LIBXML_DTDLOAD / LIBXML_DTDATTR, so
// the default options literal here suppresses the finding.
$xml = $_GET['xml'];
$doc = simplexml_load_string($xml, "SimpleXMLElement", 0);
echo $doc->title;
