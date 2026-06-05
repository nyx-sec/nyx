<?php
// SSRF — unsupported fixture.
// Entry is a class method; test sets confidence = Low.
// Expected verdict: Unsupported

class HttpClient {
    public function fetch($url) {
        $content = @file_get_contents($url);
        if ($content !== false) {
            echo $content;
        }
    }
}
