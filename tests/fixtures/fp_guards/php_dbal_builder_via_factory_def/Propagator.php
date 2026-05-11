<?php
// Doctrine DBAL builder chain whose receiver variable is NOT one of the
// canonical builder names (`qb`, `query`, `builder`, ...) so the
// receiver-name allowlist for the zero-arg query-builder suppression
// doesn't fire.  The variable is bound earlier in the body via
// `getQueryBuilder()`; the structural suppression walks back to the
// receiver's defining call to recognise it as a builder regardless of
// the local's name.  Real-world appearance: nextcloud
// `lib/private/Files/Cache/Propagator.php` uses
// `$forUpdate = $this->connection->getQueryBuilder()` for the SELECT
// FOR UPDATE row lock then chains `->select(...)->from(...)->where(...)
// ->orderBy(...)->forUpdate()->executeQuery()`.

namespace OC\Files\Cache;

class Propagator
{
    private $connection;
    private $storage;

    const MAX_RETRIES = 5;

    public function propagateChange(array $parents, int $time, int $sizeDifference = 0): void
    {
        $parentHashes = array_map('md5', $parents);
        sort($parentHashes);

        $builder = $this->connection->getQueryBuilder();
        $hashParams = array_map(static fn (string $hash) => $builder->expr()->literal($hash), $parentHashes);

        $builder->update('filecache')
            ->set('mtime', $builder->func()->greatest('mtime', $builder->createNamedParameter($time)))
            ->where($builder->expr()->eq('storage', $builder->createNamedParameter('x')))
            ->andWhere($builder->expr()->in('path_hash', $hashParams));

        for ($i = 0; $i < self::MAX_RETRIES; $i++) {
            try {
                if ($this->connection->getDatabaseProvider() !== 'sqlite') {
                    $this->connection->beginTransaction();
                    $forUpdate = $this->connection->getQueryBuilder();
                    $forUpdate->select('fileid')
                        ->from('filecache')
                        ->where($forUpdate->expr()->eq('storage', $forUpdate->createNamedParameter('x')))
                        ->andWhere($forUpdate->expr()->in('path_hash', $hashParams))
                        ->orderBy('path_hash')
                        ->forUpdate()
                        ->executeQuery();
                    $builder->executeStatement();
                    $this->connection->commit();
                } else {
                    $builder->executeStatement();
                }
                break;
            } catch (\Exception $e) {
            }
        }
    }
}
