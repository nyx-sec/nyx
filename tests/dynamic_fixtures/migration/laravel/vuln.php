<?php
// Phase 21 (Track M.3) — Laravel migration vuln fixture.
//
// `AddUsers::up()` invokes `Schema::table` via a class-static
// fallthrough but splices a tainted column name into a raw
// `DB::statement` call.

// use Illuminate\\Database\\Migrations\\Migration;
// use Illuminate\\Database\\Schema;

class AddUsers {
    public function up() {
        $col = getenv('NYX_PAYLOAD') ?: 'email';
        // SINK: tainted column name concatenated into raw DDL.
        $stmt = "ALTER TABLE users ADD COLUMN " . $col . " TEXT";
        DBStatementWrapper::statement($stmt);
        return $stmt;
    }
}

class DBStatementWrapper {
    public static function statement($sql) {
        echo "LARAVEL_SQL: " . $sql . "\n";
    }
}
