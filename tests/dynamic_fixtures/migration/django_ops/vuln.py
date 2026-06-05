"""Phase 21 — Django Migration.operations runtime fixture."""
_NYX_ADAPTER_MARKER = "from django.db import migrations"

import os


class _RunSQL:
    def __init__(self, sql):
        self.sql = sql


class Migration:
    operations = [
        _RunSQL(
            "CREATE INDEX idx_"
            + (os.environ.get("NYX_PAYLOAD") or "users")
            + " ON users(name)"
        )
    ]
