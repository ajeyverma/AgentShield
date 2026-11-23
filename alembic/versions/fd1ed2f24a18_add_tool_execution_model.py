"""add_tool_execution_model

Revision ID: fd1ed2f24a18
Revises: 1de2be623092
Create Date: 2026-11-23 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'fd1ed2f24a18'
down_revision: Union[str, Sequence[str], None] = '1de2be623092'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: add tool_executions table."""
    op.create_table(
        'tool_executions',
        sa.Column('request_id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('agent_id', sa.String(length=36), nullable=False),
        sa.Column('tool_name', sa.String(length=64), nullable=False),
        sa.Column('action_name', sa.String(length=64), nullable=False),
        sa.Column('canonical_argument_hash', sa.String(length=64), nullable=False),
        sa.Column('arguments_json', sa.Text(), nullable=True),
        sa.Column('idempotency_key', sa.String(length=128), nullable=True),
        sa.Column('decision', sa.String(length=32), nullable=False),
        sa.Column('decision_id', sa.String(length=36), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('approval_id', sa.String(length=36), nullable=True),
        sa.Column('grant_id', sa.String(length=36), nullable=True),
        sa.Column('result_json', sa.Text(), nullable=True),
        sa.Column('error_code', sa.String(length=64), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('duration_ms', sa.Float(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('tool_executions', schema=None) as batch_op:
        batch_op.create_index('ix_exec_idempotency', ['user_id', 'idempotency_key'], unique=False)
        batch_op.create_index('ix_exec_user_created', ['user_id', 'created_at'], unique=False)
        batch_op.create_index('ix_exec_user_status', ['user_id', 'status'], unique=False)
        batch_op.create_index('ix_exec_user_tool', ['user_id', 'tool_name'], unique=False)
        batch_op.create_index(batch_op.f('ix_tool_executions_agent_id'), ['agent_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_tool_executions_canonical_argument_hash'), ['canonical_argument_hash'], unique=False)
        batch_op.create_index(batch_op.f('ix_tool_executions_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_tool_executions_decision'), ['decision'], unique=False)
        batch_op.create_index(batch_op.f('ix_tool_executions_idempotency_key'), ['idempotency_key'], unique=False)
        batch_op.create_index(batch_op.f('ix_tool_executions_request_id'), ['request_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_tool_executions_status'), ['status'], unique=False)
        batch_op.create_index(batch_op.f('ix_tool_executions_tool_name'), ['tool_name'], unique=False)
        batch_op.create_index(batch_op.f('ix_tool_executions_user_id'), ['user_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('tool_executions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_tool_executions_user_id'))
        batch_op.drop_index(batch_op.f('ix_tool_executions_tool_name'))
        batch_op.drop_index(batch_op.f('ix_tool_executions_status'))
        batch_op.drop_index(batch_op.f('ix_tool_executions_request_id'))
        batch_op.drop_index(batch_op.f('ix_tool_executions_idempotency_key'))
        batch_op.drop_index(batch_op.f('ix_tool_executions_decision'))
        batch_op.drop_index(batch_op.f('ix_tool_executions_created_at'))
        batch_op.drop_index(batch_op.f('ix_tool_executions_canonical_argument_hash'))
        batch_op.drop_index(batch_op.f('ix_tool_executions_agent_id'))
        batch_op.drop_index('ix_exec_user_tool')
        batch_op.drop_index('ix_exec_user_status')
        batch_op.drop_index('ix_exec_user_created')
        batch_op.drop_index('ix_exec_idempotency')

    op.drop_table('tool_executions')
