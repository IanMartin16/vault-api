"""Add missing performance indexes

Revision ID: f6e5e3c2ceae
Revises: 001_initial
Create Date: 2026-04-26

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f6e5e3c2ceae'
down_revision = '001_initial'
branch_labels = None
depends_on = None


def upgrade():
    # Add indexes to projects table
    op.create_index('ix_projects_owner_id', 'projects', ['owner_id'], unique=False)
    op.create_index('ix_projects_created_at', 'projects', ['created_at'], unique=False)
    
    # Add indexes to secrets table
    op.create_index('ix_secrets_project_id', 'secrets', ['project_id'], unique=False)
    op.create_index('ix_secrets_created_by', 'secrets', ['created_by'], unique=False)
    op.create_index('ix_secrets_is_deleted', 'secrets', ['is_deleted'], unique=False)
    op.create_index('ix_secrets_created_at', 'secrets', ['created_at'], unique=False)


def downgrade():
    # Remove indexes from secrets table
    op.drop_index('ix_secrets_created_at', table_name='secrets')
    op.drop_index('ix_secrets_is_deleted', table_name='secrets')
    op.drop_index('ix_secrets_created_by', table_name='secrets')
    op.drop_index('ix_secrets_project_id', table_name='secrets')
    
    # Remove indexes from projects table
    op.drop_index('ix_projects_created_at', table_name='projects')
    op.drop_index('ix_projects_owner_id', table_name='projects')