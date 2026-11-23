"""add_security_decision_model

Revision ID: 514062e1462e
Revises: c9b3b265c996
Create Date: 2026-11-23 16:35:59.307242

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '514062e1462e'
down_revision: Union[str, Sequence[str], None] = 'c9b3b265c996'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: add security_decisions."""
    op.create_table(
        'security_decisions',
        sa.Column('request_id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('agent_id', sa.String(length=36), nullable=False),
        sa.Column('decision', sa.String(length=32), nullable=False),
        sa.Column('risk_score', sa.Float(), nullable=False),
        sa.Column('risk_level', sa.String(length=32), nullable=False),
        sa.Column('reasons_json', sa.Text(), nullable=True),
        sa.Column('matched_policy_ids_json', sa.Text(), nullable=True),
        sa.Column('policy_version', sa.Integer(), nullable=False),
        sa.Column('approval_required', sa.Boolean(), nullable=False),
        sa.Column('approval_id', sa.String(length=36), nullable=True),
        sa.Column('evaluation_duration_ms', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('security_decisions', schema=None) as batch_op:
        batch_op.create_index('ix_decision_user_created', ['user_id', 'created_at'], unique=False)
        batch_op.create_index('ix_decision_user_decision', ['user_id', 'decision'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_decisions_agent_id'), ['agent_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_decisions_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_decisions_decision'), ['decision'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_decisions_request_id'), ['request_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_decisions_risk_level'), ['risk_level'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_decisions_user_id'), ['user_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('security_decisions', schema=None) as batch_op:
        batch_op.drop_index('ix_decision_user_created')
        batch_op.drop_index('ix_decision_user_decision')
        batch_op.drop_index(batch_op.f('ix_security_decisions_user_id'))
        batch_op.drop_index(batch_op.f('ix_security_decisions_risk_level'))
        batch_op.drop_index(batch_op.f('ix_security_decisions_request_id'))
        batch_op.drop_index(batch_op.f('ix_security_decisions_decision'))
        batch_op.drop_index(batch_op.f('ix_security_decisions_created_at'))
        batch_op.drop_index(batch_op.f('ix_security_decisions_agent_id'))

    op.drop_table('security_decisions')
