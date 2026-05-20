<?php
// Phase 19 (Track M.1) — class-method vuln fixture for PHP.
//
// UserService::run concatenates user input into a shell command;
// default ctor, no stubbed deps needed.

class UserService {
    public function __construct() {}

    public function run($input) {
        // SINK: tainted input → shell.
        return shell_exec('echo ' . $input);
    }
}
