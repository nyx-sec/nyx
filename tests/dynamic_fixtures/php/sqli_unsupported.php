<?php
// SQL injection — unsupported fixture.
// Entry is a class method — entry kind unsupported.
// Test sets confidence = Low to get Unsupported(ConfidenceTooLow).
// Expected verdict: Unsupported

class UserRepository {
    public function findUser($name) {
        $query = "SELECT * FROM users WHERE name='" . $name . "'";
        echo $query . "\n";
    }
}
