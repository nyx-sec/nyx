"""Phase 21 — Django migration benign control."""
_NYX_ADAPTER_MARKER = "from django.db import migrations"


def upgrade(table_name="users"):
    safe = "".join(c for c in str(table_name) if c.isalnum() or c == "_")
    return "CREATE INDEX idx_" + safe + " ON users(name)"


class Migration:
    operations = []
