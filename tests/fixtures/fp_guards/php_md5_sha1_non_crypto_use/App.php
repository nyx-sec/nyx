<?php
// FP-guard fixture: md5() / sha1() in non-cryptographic consuming
// contexts.  Distilled from nextcloud DAV / file-cache / theming
// modules and phpmyadmin Controllers / Display.  None of these
// callsites should fire `php.crypto.md5` / `php.crypto.sha1`.

class CalendarObject {
    public string $data = '';
    private $cache;
    private $q;

    public function getETag(): string {
        return '"' . md5($this->data) . '"';
    }

    public function rowFor(string $objectData): array {
        return [
            'etag' => md5($objectData),
            'size' => strlen($objectData),
        ];
    }

    public function memo(string $favoriteTableName): array {
        $row = [];
        $row['table_name_hash'] = md5($favoriteTableName);
        return $row;
    }

    public function lazyHash(string $table, array &$tables): void {
        $tables[$table]['hash'] ??= md5($table);
    }

    public function trio(string $sql): array {
        $sqlMd5 = md5($sql);
        $tableHash = md5($sql . '.t');
        $etag = md5($sql . '.e');
        return [$sqlMd5, $tableHash, $etag];
    }

    public function indexByCol(array $columnNames): array {
        $columnNamesHashes = [];
        foreach ($columnNames as $col) {
            $columnNamesHashes[$col] = md5($col);
        }
        return $columnNamesHashes;
    }

    public function fetch(array $arr, string $x): mixed {
        return $arr[md5($x)] ?? null;
    }

    public function recoveryKeyId(): string {
        return 'recoveryKey_' . substr(md5((string)time()), 0, 8);
    }

    public function getCacheBuster(string $version): string {
        return substr(sha1($version), 0, 8);
    }

    public function lookup(string $uid): mixed {
        return $this->cache->get(sha1($uid));
    }

    public function safeStorageId(string $storageId): string {
        if (strlen($storageId) > 64) {
            $storageId = md5($storageId);
        }
        return $storageId;
    }
}
