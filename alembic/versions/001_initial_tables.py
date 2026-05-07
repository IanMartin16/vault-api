"""Create initial tables

Revision ID: 001_initial
Revises: 
Create Date: 2025-01-23

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import uuid

revision = '001_initial'
down_revision = None
branch_labels = None
depends_on = None


user_plan_enum = postgresql.ENUM(
    'free',
    'starter',
    'pro',
    'enterprise',
    name='user_plan',
    create_type=False
)


def upgrade() -> None:
    # Create enum type safely
    op.execute("""
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_plan') THEN
            CREATE TYPE user_plan AS ENUM ('free', 'starter', 'pro', 'enterprise');
        END IF;
    END$$;
    """)

    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('email', sa.String(255), unique=True, nullable=False, index=True),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(255)),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true')),
        sa.Column('is_verified', sa.Boolean(), server_default=sa.text('false')),
        sa.Column(
            'plan',
            user_plan_enum,
            server_default='free',
            nullable=False
        ),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('last_login', sa.DateTime())
    )
    
    # Projects table
    op.create_table(
        'projects',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('owner_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('description', sa.String(500)),
        sa.Column('environment', sa.String(50), server_default='production'),
        sa.Column('dek_salt', sa.String(255), nullable=False),
        sa.Column('color', sa.String(7), default='#3B82F6'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now(), onupdate=sa.func.now())
    )
    
    # Secrets table
    op.create_table(
        'secrets',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('projects.id'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('key', sa.String(255), nullable=False, index=True),
        sa.Column('description', sa.String(500)),
        sa.Column('encrypted_value', postgresql.JSON(), nullable=False),
        sa.Column('version', sa.Integer(), server_default=sa.text('1'), nullable=False),
        sa.Column('tags', postgresql.JSON(), server_default=sa.text("'[]'::json")),
        sa.Column('is_deleted', sa.Boolean(), server_default=sa.text('false')),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.Column('last_accessed_at', sa.DateTime()),
        sa.UniqueConstraint('project_id', 'key', name='uq_project_key')
    )
    
    # Secret versions table
    op.create_table(
        'secret_versions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('secret_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('secrets.id'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('encrypted_value', postgresql.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now())
    )
    
    # API Keys table
    op.create_table(
        'api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('projects.id')),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('key_hash', sa.String(64), unique=True, nullable=False, index=True),
        sa.Column('key_prefix', sa.String(20), nullable=False),
        sa.Column('scopes', sa.String(500), server_default='projects:read,secrets:read,secrets:reveal'),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true')),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('expires_at', sa.DateTime()),
        sa.Column('last_used_at', sa.DateTime())
    )
    
    # Project members table
    op.create_table(
        'project_members',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('projects.id'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('role', sa.String(50), default='member'),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('invited_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'))
    )
    
    # Audit logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('projects.id')),
        sa.Column('secret_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('secrets.id')),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('resource_type', sa.String(50), nullable=False),
        sa.Column('resource_id', sa.String(100)),
        sa.Column('ip_address', sa.String(45)),
        sa.Column('user_agent', sa.String(500)),
        sa.Column('api_key_id', postgresql.UUID(as_uuid=True)),
        sa.Column('request_method', sa.String(10)),
        sa.Column('request_path', sa.String(500)),
        sa.Column('status_code', sa.Integer()),
        sa.Column('event_metadata', postgresql.JSON(), server_default=sa.text("'{}'::json")),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now(), index=True)
    )


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('project_members')
    op.drop_table('api_keys')
    op.drop_table('secret_versions')
    op.drop_table('secrets')
    op.drop_table('projects')
    op.drop_table('users')
    op.execute("DROP TYPE IF EXISTS user_plan")