<?php
// File I/O — unsupported fixture.
// Entry is a class method; test sets confidence = Low.
// Expected verdict: Unsupported

class FileServer {
    public function serve($path) {
        $content = @file_get_contents($path);
        if ($content !== false) {
            echo $content;
        }
    }
}
