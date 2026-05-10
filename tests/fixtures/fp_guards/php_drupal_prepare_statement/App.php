<?php
// Drupal Database\Connection convention: `prepareStatement` returns a
// statement object that carries the SQL template; binding happens
// separately via `$stmt->execute($values, $opts)` with values shipped
// out of band.  The structural cfg-unguarded-sink rule must treat
// `prepareStatement` as a SQL_QUERY sanitizer the same way it treats
// `prepare`, otherwise every Drupal Query subclass surfaces an FP at
// the execute call.

class DrupalQueryWrapper
{
    private $connection;
    private $queryOptions;

    public function execute()
    {
        $stmt = $this->connection->prepareStatement((string) $this, $this->queryOptions, true);
        try {
            $stmt->execute([], $this->queryOptions);
            return $stmt->rowCount();
        } catch (\Exception $e) {
            $this->connection->exceptionHandler()->handleExecutionException($e, $stmt, [], $this->queryOptions);
        }

        return null;
    }

    public function executeUpdate($values)
    {
        $stmt = $this->connection->prepareStatement((string) $this, $this->queryOptions, true);
        try {
            $stmt->execute($values, $this->queryOptions);
            return $stmt->rowCount();
        } catch (\Exception $e) {
            $this->connection->exceptionHandler()->handleExecutionException($e, $stmt, $values, $this->queryOptions);
        }

        return null;
    }
}
