<?php
// Negative case: the foreach iterates a parameter (not a literal-keyed
// array), so the suppression must NOT fire and the structural rule must
// still emit cfg-unguarded-sink for the SQL_QUERY sink.

namespace OC\DB;

class UnsafeBypass
{
    public function badQuery($connection, array $userVariables): bool
    {
        foreach ($userVariables as $var => $val) {
            $connection->executeQuery("SHOW VARIABLES LIKE '$var'");
        }
        return true;
    }
}
