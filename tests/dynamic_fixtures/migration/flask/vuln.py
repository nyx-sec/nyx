"""Phase 21 (Track M.3) — Flask-Migrate / Alembic migration vuln.

Alembic revisions declare an `upgrade()` function that issues DDL
through `op.execute(...)`.  The vuln fixture splices a tainted column
name into the statement via raw string concat.
"""
_NYX_ADAPTER_MARKER = "from alembic import op"
revision = "abc123def4"
down_revision = None


class _Op:
    def execute(self, sql):
        print("ALEMBIC_SQL:", sql)


op = _Op()


def upgrade(column_name="email"):
    # SINK: tainted column name spliced into raw DDL.
    op.execute("ALTER TABLE users ADD COLUMN " + str(column_name) + " TEXT")
