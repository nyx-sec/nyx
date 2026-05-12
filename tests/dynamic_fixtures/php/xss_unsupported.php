<?php
// XSS — unsupported fixture.
// Entry is a class method; test sets confidence = Low.
// Expected verdict: Unsupported

class TemplateEngine {
    public function render($input) {
        echo '<html><body>' . $input . '</body></html>' . "\n";
    }
}
