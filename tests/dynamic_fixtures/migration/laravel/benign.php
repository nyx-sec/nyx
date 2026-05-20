<?php
// Phase 21 — Laravel migration benign control.
// use Illuminate\\Database\\Migrations\\Migration;

class AddUsers {
    public function up() {
        $col = getenv('NYX_PAYLOAD') ?: 'email';
        $safe = preg_replace('/[^A-Za-z0-9_]/', '_', $col);
        $stmt = "ALTER TABLE users ADD COLUMN " . $safe . " TEXT";
        echo "LARAVEL_SQL: " . $stmt . "\n";
        return $stmt;
    }
}
