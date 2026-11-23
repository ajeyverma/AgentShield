"""add_phase10_approval_policy_tables

Revision ID: 7a8e910b2c3d
Revises: 3b16b8062d4b
Create Date: 2026-11-23 22:42:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7a8e910b2c3d'
down_revision: Union[str, Sequence[str], None] = '3b16b8062d4b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema for Phase 10: Human Approval and Policy Management."""
    # 1. users: add role
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('role', sa.String(length=32), server_default='OWNER', nullable=False))
        batch_op.create_index(batch_op.f('ix_users_role'), ['role'], unique=False)

    # 2. approval_requests: add extended tracking columns
    with op.batch_alter_table('approval_requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('execution_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('tenant_id', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('integration_type', sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column('resource', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('risk_score', sa.Float(), server_default='0.0', nullable=False))
        batch_op.add_column(sa.Column('threat_findings_json', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('policy_version', sa.Integer(), server_default='1', nullable=False))
        batch_op.add_column(sa.Column('canonical_argument_hash', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('arguments_json', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('reviewed_by', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('reviewer_role', sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('review_comment', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('rejection_reason', sa.Text(), nullable=True))
        batch_op.create_index(batch_op.f('ix_approval_requests_execution_id'), ['execution_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_approval_requests_tenant_id'), ['tenant_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_approval_requests_canonical_argument_hash'), ['canonical_argument_hash'], unique=False)
        batch_op.create_index('ix_approval_tenant_status', ['tenant_id', 'status'], unique=False)

    # 3. policies: add scopes, priority, conditions, decision, requirements
    with op.batch_alter_table('policies', schema=None) as batch_op:
        batch_op.add_column(sa.Column('priority', sa.Integer(), server_default='100', nullable=False))
        batch_op.add_column(sa.Column('tenant_id', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('agent_scope', sa.String(length=255), server_default='*', nullable=False))
        batch_op.add_column(sa.Column('integration_scope', sa.String(length=64), server_default='*', nullable=False))
        batch_op.add_column(sa.Column('tool_scope', sa.String(length=128), server_default='*', nullable=False))
        batch_op.add_column(sa.Column('action_scope', sa.String(length=128), server_default='*', nullable=False))
        batch_op.add_column(sa.Column('resource_scope', sa.String(length=255), server_default='*', nullable=False))
        batch_op.add_column(sa.Column('conditions_json', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('decision', sa.String(length=32), server_default='ASK_HUMAN', nullable=False))
        batch_op.add_column(sa.Column('approval_requirements_json', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('created_by', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('updated_by', sa.String(length=36), nullable=True))
        batch_op.create_index(batch_op.f('ix_policies_tenant_id'), ['tenant_id'], unique=False)
        batch_op.create_index('ix_policy_user_priority', ['user_id', 'priority'], unique=False)

    # 4. approval_history
    op.create_table(
        'approval_history',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('approval_id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('action', sa.String(length=32), nullable=False),
        sa.Column('previous_status', sa.String(length=32), nullable=True),
        sa.Column('new_status', sa.String(length=32), nullable=False),
        sa.Column('performed_by', sa.String(length=36), nullable=False),
        sa.Column('performer_role', sa.String(length=32), nullable=True),
        sa.Column('comment', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['approval_id'], ['approval_requests.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('approval_history', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_approval_history_approval_id'), ['approval_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_approval_history_user_id'), ['user_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_approval_history_created_at'), ['created_at'], unique=False)
        batch_op.create_index('ix_approval_hist_appr_created', ['approval_id', 'created_at'], unique=False)

    # 5. policy_versions
    op.create_table(
        'policy_versions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('policy_id', sa.String(length=36), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('category', sa.String(length=64), nullable=False),
        sa.Column('enforcement_mode', sa.String(length=32), nullable=False),
        sa.Column('priority', sa.Integer(), server_default='100', nullable=False),
        sa.Column('decision', sa.String(length=32), nullable=False),
        sa.Column('agent_scope', sa.String(length=255), server_default='*', nullable=False),
        sa.Column('integration_scope', sa.String(length=64), server_default='*', nullable=False),
        sa.Column('tool_scope', sa.String(length=128), server_default='*', nullable=False),
        sa.Column('action_scope', sa.String(length=128), server_default='*', nullable=False),
        sa.Column('resource_scope', sa.String(length=255), server_default='*', nullable=False),
        sa.Column('conditions_json', sa.Text(), nullable=True),
        sa.Column('rules_json', sa.Text(), nullable=True),
        sa.Column('approval_requirements_json', sa.Text(), nullable=True),
        sa.Column('is_enabled', sa.Boolean(), default=True, nullable=False),
        sa.Column('changed_by', sa.String(length=36), nullable=False),
        sa.Column('change_reason', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['policy_id'], ['policies.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('policy_versions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_policy_versions_policy_id'), ['policy_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_policy_versions_created_at'), ['created_at'], unique=False)
        batch_op.create_index('ix_policy_version_lookup', ['policy_id', 'version'], unique=False)

    # 6. emergency_controls
    op.create_table(
        'emergency_controls',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), nullable=True),
        sa.Column('control_type', sa.String(length=64), nullable=False),
        sa.Column('target_identifier', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), default=True, nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('activated_by', sa.String(length=36), nullable=False),
        sa.Column('activated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_by', sa.String(length=36), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revocation_reason', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('emergency_controls', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_emergency_controls_user_id'), ['user_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_emergency_controls_tenant_id'), ['tenant_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_emergency_controls_control_type'), ['control_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_emergency_controls_target_identifier'), ['target_identifier'], unique=False)
        batch_op.create_index(batch_op.f('ix_emergency_controls_is_active'), ['is_active'], unique=False)
        batch_op.create_index('ix_emergency_user_active', ['user_id', 'is_active'], unique=False)
        batch_op.create_index('ix_emergency_type_target', ['control_type', 'target_identifier', 'is_active'], unique=False)


def downgrade() -> None:
    """Downgrade schema to remove Phase 10 tables and columns."""
    op.drop_table('emergency_controls')
    op.drop_table('policy_versions')
    op.drop_table('approval_history')

    with op.batch_alter_table('policies', schema=None) as batch_op:
        batch_op.drop_index('ix_policy_user_priority')
        batch_op.drop_index(batch_op.f('ix_policies_tenant_id'))
        batch_op.drop_column('updated_by')
        batch_op.drop_column('created_by')
        batch_op.drop_column('approval_requirements_json')
        batch_op.drop_column('decision')
        batch_op.drop_column('conditions_json')
        batch_op.drop_column('resource_scope')
        batch_op.drop_column('action_scope')
        batch_op.drop_column('tool_scope')
        batch_op.drop_column('integration_scope')
        batch_op.drop_column('agent_scope')
        batch_op.drop_column('tenant_id')
        batch_op.drop_column('priority')

    with op.batch_alter_table('approval_requests', schema=None) as batch_op:
        batch_op.drop_index('ix_approval_tenant_status')
        batch_op.drop_index(batch_op.f('ix_approval_requests_canonical_argument_hash'))
        batch_op.drop_index(batch_op.f('ix_approval_requests_tenant_id'))
        batch_op.drop_index(batch_op.f('ix_approval_requests_execution_id'))
        batch_op.drop_column('rejection_reason')
        batch_op.drop_column('review_comment')
        batch_op.drop_column('reviewed_at')
        batch_op.drop_column('reviewer_role')
        batch_op.drop_column('reviewed_by')
        batch_op.drop_column('arguments_json')
        batch_op.drop_column('canonical_argument_hash')
        batch_op.drop_column('policy_version')
        batch_op.drop_column('threat_findings_json')
        batch_op.drop_column('risk_score')
        batch_op.drop_column('resource')
        batch_op.drop_column('integration_type')
        batch_op.drop_column('tenant_id')
        batch_op.drop_column('execution_id')

    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_users_role'))
        batch_op.drop_column('role')
