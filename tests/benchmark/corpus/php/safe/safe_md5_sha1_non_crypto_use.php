<?php
// `md5()` and `sha1()` are pervasively used in real-world PHP for
// non-cryptographic purposes — ETag generation, cache-key / array-index
// hashing, dedup fingerprints, content-addressed identifier
// derivation.  None of these uses realises the "weak hash function"
// risk the rule names; the engine recognises the consuming context
// (variable LHS, array key, return-from-method, lookup-verb argument)
// and suppresses these structural shapes.  Genuine weak-hash crypto
// misuse — `$password_hash`, `$token`, `$signature`, `$digest` — keeps
// firing because the consumer name contains a crypto-keyword
// substring.

class CalendarObject {
    public string $data = '';
    private $cache;

    /** ETag generation — RFC-allowed weak validator, not auth. */
    public function getETag(): string {
        return '"' . md5($this->data) . '"';
    }

    /** Array-element value with an ETag-flagged key. */
    public function rowFor(string $objectData): array {
        return [
            'etag' => md5($objectData),
            'size' => strlen($objectData),
        ];
    }

    /** Subscript-LHS with a string-literal index. */
    public function memo(string $favoriteTableName): array {
        $row = [];
        $row['table_name_hash'] = md5($favoriteTableName);
        return $row;
    }

    /** Null-coalescing assignment with subscript LHS. */
    public function lazyHash(string $table, array &$tables): void {
        $tables[$table]['hash'] ??= md5($table);
    }

    /** Bare variable LHS named `*Hash` / `*Md5` / `*etag`. */
    public function trio(string $sql): array {
        $sqlMd5 = md5($sql);
        $tableHash = md5($sql . '.t');
        $etag = md5($sql . '.e');
        return [$sqlMd5, $tableHash, $etag];
    }

    /** Dynamic-index subscript LHS — receiver name carries the signal. */
    public function indexByCol(array $columnNames): array {
        $columnNamesHashes = [];
        foreach ($columnNames as $col) {
            $columnNamesHashes[$col] = md5($col);
        }
        return $columnNamesHashes;
    }

    /** md5 result used as an array index — hash-table lookup. */
    public function fetch(array $arr, string $x): mixed {
        return $arr[md5($x)] ?? null;
    }

    /** Concatenation feeding a non-crypto-named LHS. */
    public function recoveryKeyId(): string {
        return 'recoveryKey_' . substr(md5((string)time()), 0, 8);
    }

    /** Cache-buster — return from a method whose name encodes intent. */
    public function getCacheBuster(string $version): string {
        return substr(sha1($version), 0, 8);
    }

    /** Receiver with `Method`-typed lookup verb — `cache->get`/`cache->set`. */
    public function lookup(string $uid): mixed {
        return $this->cache->get(sha1($uid));
    }

    /** Cross-language non-crypto: ID hashing for DB-safe characters. */
    public function safeStorageId(string $storageId): string {
        if (strlen($storageId) > 64) {
            $storageId = md5($storageId);
        }
        return $storageId;
    }
}
