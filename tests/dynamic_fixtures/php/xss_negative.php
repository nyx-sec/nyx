<?php
// XSS — negative fixture.
// Safe: uses htmlspecialchars() before output.
// Entry: renderPage($userInput)  Cap: HTML_ESCAPE
// Expected verdict: NotConfirmed

function renderPage($userInput) {
    $safe = htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');
    echo '<html><body>' . $safe . '</body></html>' . "\n";
}
