<?php
// Vulnerable counterpart to `safe_md5_sha1_non_crypto_use.php` — these
// shapes hash sensitive credentials with `md5()` / `sha1()`.  The
// consumer names contain crypto-keyword substrings (`password`,
// `token`, `signature`, `digest`) so Layer F suppression refuses to
// fire and the pattern rule keeps emitting `php.crypto.md5` /
// `php.crypto.sha1`.

class Vault {
    /** Storing a password as md5 hash — classic weak-hash credential storage. */
    public function setPassword(string $password): void {
        $this->password = md5($password);
    }

    /** Token generation via sha1 — used as a session/credential token. */
    public function rotateToken(string $secret): string {
        $token = sha1($secret . microtime(true));
        $_SESSION['csrf_token'] = $token;
        return $token;
    }

    /** Signature comparison value built with sha1 — explicit crypto intent. */
    public function signRequest(string $payload, string $key): string {
        $signature = sha1($key . $payload);
        return $signature;
    }

    /** Compound `*_hash` name preceded by a crypto-keyword token. */
    public function storeUser(string $username, string $pwd): void {
        $pw_hash = md5($pwd);
        $this->saveUser($username, $pw_hash);
    }

    /** Returns a pre-shared digest used for HMAC-style comparison. */
    public function digest(string $msg, string $key): string {
        return sha1($key . $msg);
    }

    private function saveUser(string $u, string $pw): void {}

    public string $password = '';
}
