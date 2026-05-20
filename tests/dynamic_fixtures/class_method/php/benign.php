<?php
// Phase 19 (Track M.1) — class-method benign control for PHP.

class UserService {
    public function __construct() {}

    public function run($input) {
        return shell_exec('echo ' . escapeshellarg($input));
    }
}
