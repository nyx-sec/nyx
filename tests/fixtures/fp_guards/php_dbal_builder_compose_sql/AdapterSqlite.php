<?php
// Real nextcloud `lib/private/DB/AdapterSqlite.php` shape.  The builder is
// bound by `$this->conn->getQueryBuilder()`, and the executeStatement
// first-arg appends a constant `' ON CONFLICT DO NOTHING'` to the
// `$builder->getSQL()` accessor.  No user payload, no taint.

namespace OC\DB;

class AdapterSqlite
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

        return $this->conn->executeStatement(
            $builder->getSQL() . ' ON CONFLICT DO NOTHING',
            $builder->getParameters(),
            $builder->getParameterTypes()
        );
    }
}
