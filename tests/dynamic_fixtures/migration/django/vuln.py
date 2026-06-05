"""Phase 21 (Track M.3) — Django migration vuln fixture.

The migration declares `operations = [...]` with a
`migrations.RunSQL` op whose statement is built from an external
table name via raw string concatenation.
"""
_NYX_ADAPTER_MARKER = "from django.db import migrations"


class _RunSQL:
    def __init__(self, sql):
        self.sql = sql


def upgrade(table_name="users"):
    # SINK: tainted table name spliced into raw DDL.
    sql = "CREATE INDEX idx_" + str(table_name) + " ON users(name)"
    op = _RunSQL(sql)
    return op


class Migration:
    operations = []
