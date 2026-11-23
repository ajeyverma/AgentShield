"""add_threat_finding_model

Revision ID: 1de2be623092
Revises: 514062e1462e
Create Date: 2026-11-23 17:06:13.646985

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1de2be623092'
down_revision: Union[str, Sequence[str], None] = '514062e1462e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: add threat_findings table."""
    op.create_table(
        'threat_findings',
        sa.Column('request_id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('agent_id', sa.String(length=36), nullable=False),
        sa.Column('detector_id', sa.String(length=64), nullable=False),
        sa.Column('threat_type', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('confidence', sa.String(length=32), nullable=False),
        sa.Column('risk_contribution', sa.Float(), nullable=False),
        sa.Column('evidence_json', sa.Text(), nullable=True),
        sa.Column('affected_resource', sa.String(length=512), nullable=True),
        sa.Column('recommended_action', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('detector_version', sa.String(length=32), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('threat_findings', schema=None) as batch_op:
        batch_op.create_index('ix_finding_user_created', ['user_id', 'created_at'], unique=False)
        batch_op.create_index('ix_finding_user_severity', ['user_id', 'severity'], unique=False)
        batch_op.create_index('ix_finding_user_status', ['user_id', 'status'], unique=False)
        batch_op.create_index(batch_op.f('ix_threat_findings_agent_id'), ['agent_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_threat_findings_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_threat_findings_detector_id'), ['detector_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_threat_findings_request_id'), ['request_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_threat_findings_severity'), ['severity'], unique=False)
        batch_op.create_index(batch_op.f('ix_threat_findings_status'), ['status'], unique=False)
        batch_op.create_index(batch_op.f('ix_threat_findings_threat_type'), ['threat_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_threat_findings_user_id'), ['user_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('threat_findings', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_threat_findings_user_id'))
        batch_op.drop_index(batch_op.f('ix_threat_findings_threat_type'))
        batch_op.drop_index(batch_op.f('ix_threat_findings_status'))
        batch_op.drop_index(batch_op.f('ix_threat_findings_severity'))
        batch_op.drop_index(batch_op.f('ix_threat_findings_request_id'))
        batch_op.drop_index(batch_op.f('ix_threat_findings_detector_id'))
        batch_op.drop_index(batch_op.f('ix_threat_findings_created_at'))
        batch_op.drop_index(batch_op.f('ix_threat_findings_agent_id'))
        batch_op.drop_index('ix_finding_user_status')
        batch_op.drop_index('ix_finding_user_severity')
        batch_op.drop_index('ix_finding_user_created')

    op.drop_table('threat_findings')
