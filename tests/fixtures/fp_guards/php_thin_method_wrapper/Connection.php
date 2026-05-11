<?php
// Thin method wrapper that forwards typed parameters to an inner sink
// call on `$this`.  Real-world equivalents: Doctrine DBAL
// `Connection::executeUpdate` delegating to `executeStatement`,
// nextcloud `lib/private/DB/Connection::executeUpdate`,
// `ConnectionAdapter::executeQuery` wrapping `$this->inner->executeQuery`,
// Drupal `Connection::query` thin overrides per driver.  Because every
// argument to the inner call is the wrapper's own parameter, the
// `cfg-unguarded-sink` structural rule has zero signal at the wrapper
// site; the real signal is at callers, which the taint engine handles.

namespace OC\DB;

class Connection
{
    private $inner;

    public function executeUpdate(string $sql, array $params = [], array $types = []): int
    {
        return $this->executeStatement($sql, $params, $types);
    }

    public function executeStatement($sql, array $params = [], array $types = []): int
    {
        return 0;
    }
}

class ConnectionAdapter
{
    private $inner;

    public function executeQuery(string $sql, array $params = [], $types = [])
    {
        return new ResultAdapter($this->inner->executeQuery($sql, $params, $types));
    }

    public function executeStatement($sql, array $params = [], array $types = []): int
    {
        return $this->inner->executeStatement($sql, $params, $types);
    }
}

class ResultAdapter
{
    public function __construct($inner) {}
}
