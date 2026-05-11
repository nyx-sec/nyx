<?php
// Doctrine DBAL `AbstractPlatform::get*SQL(...)` family of safe DDL
// builders (`getTruncateTableSQL`, `getCreateTableSQL`,
// `getDropTableSQL`, `getAlterTableSQL`, etc.).  These methods receive
// schema identifiers and emit DBMS-specific DDL with no user-supplied
// payload bytes.  Real-world appearance: nextcloud
// `apps/user_ldap/lib/Migration/Version*.php` and core/Migrations/
// `Version*.php` build a `$sql` local from a platform DDL builder then
// pass it to `$this->dbc->executeStatement($sql)`.  The flat
// `executeStatement` SQL_QUERY sink rule fires structurally; the
// suppression must walk back to the local's defining call to recognise
// the safe accessor.

namespace OC\Migrations;

class TruncateBackupTableMigration
{
    private $dbc;

    public function postSchemaChange(\IOutput $output, \Closure $schemaClosure, array $options): void
    {
        $schema = $schemaClosure();
        if ($schema->hasTable('ldap_group_mapping_backup')) {
            $sql = $this->dbc->getDatabasePlatform()->getTruncateTableSQL('`*PREFIX*ldap_group_mapping_backup`', false);
            $this->dbc->executeStatement($sql);
        }
    }

    public function preInline(\IOutput $output, \Closure $schemaClosure, array $options): void
    {
        // Direct method-call arg variant.
        $this->dbc->executeStatement(
            $this->dbc->getDatabasePlatform()->getTruncateTableSQL('`*PREFIX*tmp`', false)
        );
    }
}
