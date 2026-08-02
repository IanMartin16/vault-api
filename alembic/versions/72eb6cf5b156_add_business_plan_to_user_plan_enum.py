"""Add business plan to user_plan enum

Revision ID: 72eb6cf5b156
Revises: 274dfca33fd5
Create Date: 2026-08-02 16:17:37.350632

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '72eb6cf5b156'
down_revision = '274dfca33fd5'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ALTER TYPE ... ADD VALUE can't run inside a transaction block, and
    # Alembic wraps migrations in one. Committing first lets it execute.
    op.execute("COMMIT")
    op.execute("ALTER TYPE user_plan ADD VALUE IF NOT EXISTS 'business'")


def downgrade() -> None:
    # PostgreSQL can't remove enum values without recreating the type and
    # rewriting every column that uses it. Not worth it for an additive change.
    pass