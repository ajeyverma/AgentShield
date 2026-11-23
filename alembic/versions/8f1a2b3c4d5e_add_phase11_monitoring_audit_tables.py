"""add_phase11_monitoring_audit_tables

Revision ID: 8f1a2b3c4d5e
Revises: 7a8e910b2c3d
Create Date: 2026-11-23 23:58:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8f1a2b3c4d5e'
down_revision: Union[str, Sequence[str], None] = '7a8e910b2c3d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema for Phase 11: Monitoring, Auditing & Advanced Security Testing."""
    # 1. audit_logs: add hash chain and actor columns
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('tenant_id', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('actor_id', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('action', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('target', sa.String(length=256), nullable=True))
        batch_op.add_column(sa.Column('result', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('sequence_number', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('previous_hash', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('current_hash', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('canonical_payload', sa.Text(), nullable=True))
        batch_op.create_index(batch_op.f('ix_audit_logs_tenant_id'), ['tenant_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_logs_current_hash'), ['current_hash'], unique=False)

    # 2. security_events table
    op.create_table(
        'security_events',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('event_version', sa.String(length=16), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), nullable=False),
        sa.Column('actor_id', sa.String(length=64), nullable=False),
        sa.Column('agent_id', sa.String(length=64), nullable=True),
        sa.Column('integration_type', sa.String(length=32), nullable=True),
        sa.Column('session_id', sa.String(length=64), nullable=True),
        sa.Column('request_id', sa.String(length=64), nullable=True),
        sa.Column('execution_id', sa.String(length=64), nullable=True),
        sa.Column('correlation_id', sa.String(length=64), nullable=False),
        sa.Column('trace_id', sa.String(length=64), nullable=False),
        sa.Column('span_id', sa.String(length=32), nullable=False),
        sa.Column('parent_span_id', sa.String(length=32), nullable=True),
        sa.Column('event_type', sa.String(length=128), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('source_component', sa.String(length=64), nullable=False),
        sa.Column('action', sa.String(length=128), nullable=False),
        sa.Column('decision', sa.String(length=32), nullable=True),
        sa.Column('resource', sa.String(length=512), nullable=True),
        sa.Column('metadata_json', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_security_events_timestamp', 'security_events', ['timestamp'], unique=False)
    op.create_index('ix_security_events_tenant_id', 'security_events', ['tenant_id'], unique=False)
    op.create_index('ix_security_events_correlation_id', 'security_events', ['correlation_id'], unique=False)
    op.create_index('ix_security_events_trace_id', 'security_events', ['trace_id'], unique=False)
    op.create_index('ix_security_events_event_type', 'security_events', ['event_type'], unique=False)
    op.create_index('ix_security_events_severity', 'security_events', ['severity'], unique=False)

    # 3. audit_checkpoints table
    op.create_table(
        'audit_checkpoints',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), nullable=False),
        sa.Column('start_sequence', sa.Integer(), nullable=False),
        sa.Column('end_sequence', sa.Integer(), nullable=False),
        sa.Column('root_hash', sa.String(length=64), nullable=False),
        sa.Column('record_count', sa.Integer(), nullable=False),
        sa.Column('is_verified', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_audit_checkpoints_tenant_id', 'audit_checkpoints', ['tenant_id'], unique=False)

    # 4. security_alerts table
    op.create_table(
        'security_alerts',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), nullable=False),
        sa.Column('rule_id', sa.String(length=64), nullable=False),
        sa.Column('rule_name', sa.String(length=128), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('category', sa.String(length=64), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('affected_agent_id', sa.String(length=64), nullable=True),
        sa.Column('correlation_id', sa.String(length=64), nullable=True),
        sa.Column('evidence_json', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_security_alerts_tenant_id', 'security_alerts', ['tenant_id'], unique=False)
    op.create_index('ix_security_alerts_status', 'security_alerts', ['status'], unique=False)
    op.create_index('ix_security_alerts_severity', 'security_alerts', ['severity'], unique=False)

    # 5. incidents table
    op.create_table(
        'incidents',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('affected_agent_ids_json', sa.Text(), nullable=True),
        sa.Column('related_alert_ids_json', sa.Text(), nullable=True),
        sa.Column('related_event_ids_json', sa.Text(), nullable=True),
        sa.Column('assigned_to', sa.String(length=64), nullable=True),
        sa.Column('resolution_summary', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_incidents_tenant_id', 'incidents', ['tenant_id'], unique=False)
    op.create_index('ix_incidents_status', 'incidents', ['status'], unique=False)
    op.create_index('ix_incidents_severity', 'incidents', ['severity'], unique=False)

    # 6. incident_notes table
    op.create_table(
        'incident_notes',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('incident_id', sa.String(length=36), nullable=False),
        sa.Column('author_id', sa.String(length=64), nullable=False),
        sa.Column('author_role', sa.String(length=32), nullable=True),
        sa.Column('note', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_incident_notes_incident_id', 'incident_notes', ['incident_id'], unique=False)

    # 7. incident_history table
    op.create_table(
        'incident_history',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('incident_id', sa.String(length=36), nullable=False),
        sa.Column('previous_status', sa.String(length=32), nullable=True),
        sa.Column('new_status', sa.String(length=32), nullable=False),
        sa.Column('changed_by', sa.String(length=64), nullable=False),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_incident_history_incident_id', 'incident_history', ['incident_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('incident_history')
    op.drop_table('incident_notes')
    op.drop_table('incidents')
    op.drop_table('security_alerts')
    op.drop_table('audit_checkpoints')
    op.drop_table('security_events')
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.drop_column('canonical_payload')
        batch_op.drop_column('current_hash')
        batch_op.drop_column('previous_hash')
        batch_op.drop_column('sequence_number')
        batch_op.drop_column('result')
        batch_op.drop_column('target')
        batch_op.drop_column('action')
        batch_op.drop_column('actor_id')
        batch_op.drop_column('tenant_id')
