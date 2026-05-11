<?php
// Doctrine DBAL `QueryBuilder` chain.  The terminal `executeQuery()` /
// `executeStatement()` verbs take zero positional args, the SQL was
// bound earlier on the chain via `select` / `from` / `where` /
// `setParameter` calls (parameterised, no concatenation).  A flat
// `executeQuery` Sink rule fires here regardless of taint because the
// callee suffix matches; the structural cfg-unguarded-sink finding
// must be suppressed when the call has no args.  Distilled from
// nextcloud apps/dav (CalDavBackend / CardDavBackend) and lib/private
// /DB usage.

class CalendarRepository
{
    private $db;

    public function getDeletedCalendars(int $deletedBefore): array
    {
        $qb = $this->db->getQueryBuilder();
        $qb->select(['id', 'deleted_at'])
            ->from('calendars')
            ->where($qb->expr()->isNotNull('deleted_at'))
            ->andWhere($qb->expr()->lt('deleted_at', $qb->createNamedParameter($deletedBefore)));
        $result = $qb->executeQuery();
        $calendars = [];
        while (($row = $result->fetchAssociative()) !== false) {
            $calendars[] = [
                'id' => (int) $row['id'],
                'deleted_at' => (int) $row['deleted_at'],
            ];
        }
        $result->closeCursor();

        return $calendars;
    }

    public function deleteExpired(int $expiry): int
    {
        $qb = $this->db->getQueryBuilder();
        $qb->delete('calendars')
            ->where($qb->expr()->lt('deleted_at', $qb->createNamedParameter($expiry)));

        return $qb->executeStatement();
    }

    public function restoreCalendar(int $id): void
    {
        // Closure-wrapped variant: the inner $update->executeStatement()
        // is reached via find_classifiable_inner_call descent so the
        // CFG node represents the outer atomic() call but the callee
        // text resolves to update.executeStatement.  Receiver "update"
        // matches the verb-named builder allowlist; the structural
        // suppression must still fire.
        $this->atomic(function () use ($id): void {
            $qb = $this->db->getQueryBuilder();
            $update = $qb->update('calendars')
                ->set('deleted_at', $qb->createNamedParameter(null))
                ->where($qb->expr()->eq('id', $qb->createNamedParameter($id)));
            $update->executeStatement();
        });
    }
}
