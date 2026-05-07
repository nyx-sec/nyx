<?php
// Baseline: expression is a compile-time constant.  No taint reaches
// SimpleXMLElement::xpath so no XPATH_INJECTION finding fires.
$xml = simplexml_load_file("users.xml");
$nodes = $xml->xpath("//user[@role='admin']");
