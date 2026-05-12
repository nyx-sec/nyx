<?php
// Command injection — unsupported fixture.
// Entry is a class method; test sets confidence = Low.
// Expected verdict: Unsupported

class Runner {
    public function execute($cmd) {
        shell_exec($cmd);
    }
}
