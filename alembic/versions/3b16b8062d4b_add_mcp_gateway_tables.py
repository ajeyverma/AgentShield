"""add_mcp_gateway_tables

Revision ID: 3b16b8062d4b
Revises: fd1ed2f24a18
Create Date: 2026-11-23 20:14:43.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3b16b8062d4b'
down_revision: Union[str, Sequence[str], None] = 'fd1ed2f24a18'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to add MCP Gateway tables."""
    # 1. mcp_servers
    op.create_table(
        'mcp_servers',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('server_name', sa.String(length=128), nullable=False),
        sa.Column('server_description', sa.Text(), nullable=True),
        sa.Column('transport_type', sa.String(length=32), nullable=False),
        sa.Column('endpoint_or_command', sa.String(length=512), nullable=False),
        sa.Column('args_json', sa.Text(), nullable=True),
        sa.Column('env_json', sa.Text(), nullable=True),
        sa.Column('protocol_version', sa.String(length=32), nullable=False),
        sa.Column('capabilities_json', sa.Text(), nullable=True),
        sa.Column('connection_status', sa.String(length=32), nullable=False),
        sa.Column('is_enabled', sa.Boolean(), nullable=False),
        sa.Column('trust_classification', sa.String(length=32), nullable=False),
        sa.Column('last_connected_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('mcp_servers', schema=None) as batch_op:
        batch_op.create_index('ix_mcp_server_user_name', ['user_id', 'server_name'], unique=True)
        batch_op.create_index('ix_mcp_server_user_status', ['user_id', 'is_enabled'], unique=False)
        batch_op.create_index(batch_op.f('ix_mcp_servers_user_id'), ['user_id'], unique=False)

    # 2. mcp_sessions
    op.create_table(
        'mcp_sessions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('server_id', sa.String(length=36), nullable=False),
        sa.Column('client_id', sa.String(length=64), nullable=False),
        sa.Column('session_token', sa.String(length=128), nullable=False),
        sa.Column('transport_type', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_activity_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['server_id'], ['mcp_servers.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('mcp_sessions', schema=None) as batch_op:
        batch_op.create_index('ix_mcp_session_user_status', ['user_id', 'status'], unique=False)
        batch_op.create_index(batch_op.f('ix_mcp_sessions_client_id'), ['client_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_mcp_sessions_server_id'), ['server_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_mcp_sessions_session_token'), ['session_token'], unique=True)
        batch_op.create_index(batch_op.f('ix_mcp_sessions_user_id'), ['user_id'], unique=False)

    # 3. mcp_activities
    op.create_table(
        'mcp_activities',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('server_id', sa.String(length=36), nullable=False),
        sa.Column('session_id', sa.String(length=36), nullable=True),
        sa.Column('client_id', sa.String(length=64), nullable=True),
        sa.Column('operation_type', sa.String(length=64), nullable=False),
        sa.Column('target_name', sa.String(length=256), nullable=False),
        sa.Column('decision', sa.String(length=32), nullable=False),
        sa.Column('decision_id', sa.String(length=36), nullable=True),
        sa.Column('approval_id', sa.String(length=36), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('request_summary', sa.Text(), nullable=True),
        sa.Column('response_summary', sa.Text(), nullable=True),
        sa.Column('redaction_applied', sa.Boolean(), nullable=False),
        sa.Column('threat_count', sa.Integer(), nullable=False),
        sa.Column('duration_ms', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('mcp_activities', schema=None) as batch_op:
        batch_op.create_index('ix_mcp_act_server_op', ['server_id', 'operation_type'], unique=False)
        batch_op.create_index('ix_mcp_act_user_created', ['user_id', 'created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_mcp_activities_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_mcp_activities_decision'), ['decision'], unique=False)
        batch_op.create_index(batch_op.f('ix_mcp_activities_operation_type'), ['operation_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_mcp_activities_server_id'), ['server_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_mcp_activities_user_id'), ['user_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema to drop MCP Gateway tables."""
    with op.batch_alter_table('mcp_activities', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_mcp_activities_user_id'))
        batch_op.drop_index(batch_op.f('ix_mcp_activities_server_id'))
        batch_op.drop_index(batch_op.f('ix_mcp_activities_operation_type'))
        batch_op.drop_index(batch_op.f('ix_mcp_activities_decision'))
        batch_op.drop_index(batch_op.f('ix_mcp_activities_created_at'))
        batch_op.drop_index('ix_mcp_act_user_created')
        batch_op.drop_index('ix_mcp_act_server_op')

    op.drop_table('mcp_activities')

    with op.batch_alter_table('mcp_sessions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_mcp_sessions_user_id'))
        batch_op.drop_index(batch_op.f('ix_mcp_sessions_session_token'))
        batch_op.drop_index(batch_op.f('ix_mcp_sessions_server_id'))
        batch_op.drop_index(batch_op.f('ix_mcp_sessions_client_id'))
        batch_op.drop_index('ix_mcp_session_user_status')

    op.drop_table('mcp_sessions')

    with op.batch_alter_table('mcp_servers', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_mcp_servers_user_id'))
        batch_op.drop_index('ix_mcp_server_user_status')
        batch_op.drop_index('ix_mcp_server_user_name')

    op.drop_table('mcp_servers')
