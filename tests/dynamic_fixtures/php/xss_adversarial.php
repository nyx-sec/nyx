<?php
// XSS — adversarial collision fixture.
// Prints the XSS oracle marker unconditionally without rendering any template
// and without emitting __NYX_SINK_HIT__.
// Expected verdict: Inconclusive(OracleCollisionSuspected)
// Entry: renderPage($userInput)  Cap: HTML_ESCAPE

function renderPage($userInput) {
    // Coincidental oracle match — not an HTML render sink.
    echo "<script>NYX_XSS_CONFIRMED</script>\n";
    $x = strlen($userInput);
}
