from alembic import op

revision = "abc123def4"


def upgrade():
    op.create_table("users")


def normalize_name(name):
    return str(name)
