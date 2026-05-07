<?php
// Baseline: tainted body flows through a non-parser string operation.
// No XML parser entry point, no XXE label classification.
$xml = $_GET['xml'];
echo "<wrap>" . $xml . "</wrap>";
