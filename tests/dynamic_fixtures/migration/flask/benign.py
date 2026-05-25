"""Phase 21 — Alembic benign control."""
_NYX_ADAPTER_MARKER = "from alembic import op"
revision = "deadbeef0001"


def upgrade(column_name="email"):
    _ = column_name
    return "ALTER TABLE users ADD COLUMN email TEXT"
