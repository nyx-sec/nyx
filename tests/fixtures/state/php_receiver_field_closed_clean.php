<?php
// The connection lives on the object and close() releases it.
// Expected: no resource findings.
class Repo {
    private $conn;

    public function __construct() {
        $this->conn = new mysqli("localhost", "user", "pass", "db");
    }

    public function count() {
        return $this->conn->query("SELECT COUNT(*) FROM t");
    }

    public function close() {
        $this->conn->close();
    }
}
