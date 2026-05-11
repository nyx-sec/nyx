<?php
// Doctrine DBAL QueryBuilder pattern: the builder accumulates a
// parameterised SQL string via select / from / where / setParameter
// chains, then exposes the assembled SQL via `$qb->getSQL()`.  Real
// nextcloud `lib/private/DB/QueryBuilder/QueryBuilder.php` implements
// the terminal `executeQuery` / `executeStatement` overloads by passing
// `$this->getSQL()` plus `$this->getParameters()` to a connection.  The
// connection's `executeQuery` has a flat overload that takes a SQL
// string, so the structural cfg-unguarded-sink rule fires on the
// receiver-typed call.  A `getSQL` first arg proves the SQL was built
// via the parameterised builder API and the structural finding is noise.

namespace OC\DB\QueryBuilder;

class QueryBuilder
{
    private $connection;

    public function executeQuery(?\IDBConnection $connection = null)
    {
        if (!$connection) {
            $connection = $this->connection;
        }
        return $connection->executeQuery(
            $this->getSQL(),
            $this->getParameters(),
            $this->getParameterTypes(),
        );
    }

    public function executeStatement(?\IDBConnection $connection = null): int
    {
        if (!$connection) {
            $connection = $this->connection;
        }
        return $connection->executeStatement(
            $this->getSQL(),
            $this->getParameters(),
            $this->getParameterTypes(),
        );
    }

    public function getSQL(): string { return ''; }
    public function getParameters(): array { return []; }
    public function getParameterTypes(): array { return []; }
}
