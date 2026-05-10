<?php
// Real nextcloud `lib/private/DB/AdapterMySQL.php` shape.  The builder is
// bound by `$this->conn->getQueryBuilder()`, and the executeStatement
// first-arg wraps `$builder->getSQL()` with a `preg_replace` rewrite that
// patches the leading verb (`INSERT` -> `INSERT IGNORE`) without weaving
// any user payload.  The structural cfg-unguarded-sink rule had previously
// fired because `arg_callees[0]` is `preg_replace`, not a DBAL accessor.

namespace OC\DB;

class Connection
{
    public function getQueryBuilder() { return new \OC\DB\QueryBuilder\QueryBuilder(); }
    public function executeStatement(string $sql, array $params = [], array $types = []): int { return 0; }
}

class AdapterMySQL
{
    /** @var Connection */
    protected $conn;

    public function insertIgnoreConflict(string $table, array $values): int
    {
        $builder = $this->conn->getQueryBuilder();
        $builder->insert($table);
        foreach ($values as $key => $value) {
            $builder->setValue($key, $builder->createNamedParameter($value));
        }

        $res = $this->conn->executeStatement(
            preg_replace('/^INSERT/i', 'INSERT IGNORE', $builder->getSQL()),
            $builder->getParameters(),
            $builder->getParameterTypes()
        );

        return $res;
    }
}
