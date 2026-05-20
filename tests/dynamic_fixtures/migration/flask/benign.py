"""Phase 21 — Alembic benign control."""
_NYX_ADAPTER_MARKER = "from alembic import op"
revision = "deadbeef0001"


def upgrade(column_name="email"):
    safe = "".join(c for c in str(column_name) if c.isalnum() or c == "_")
    return "ALTER TABLE users ADD COLUMN " + safe + " TEXT"
