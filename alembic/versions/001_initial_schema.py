"""Initial schema migration for ThreatLens

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-10-14 21:00:00

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Users
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('username', sa.String(length=64), nullable=False),
        sa.Column('email', sa.String(length=128), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=32), nullable=False, server_default='analyst'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_users_username', 'users', ['username'], unique=True)
    op.create_index('ix_users_email', 'users', ['email'], unique=True)

    # 2. Ingestion Jobs
    op.create_table(
        'ingestion_jobs',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='pending'),
        sa.Column('source_format', sa.String(length=64), nullable=True),
        sa.Column('total_records', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('accepted_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('rejected_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('processed_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('failed_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('error_summary', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )

    # 3. Events
    op.create_table(
        'events',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('event_fingerprint', sa.String(length=64), nullable=False),
        sa.Column('source_format', sa.String(length=64), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('source_ip', sa.String(length=64), nullable=True),
        sa.Column('destination_ip', sa.String(length=64), nullable=True),
        sa.Column('source_port', sa.Integer(), nullable=True),
        sa.Column('destination_port', sa.Integer(), nullable=True),
        sa.Column('hostname', sa.String(length=128), nullable=True),
        sa.Column('username', sa.String(length=128), nullable=True),
        sa.Column('action', sa.String(length=64), nullable=True),
        sa.Column('severity', sa.String(length=32), nullable=True, server_default='informational'),
        sa.Column('event_type', sa.String(length=128), nullable=True),
        sa.Column('raw_message', sa.Text(), nullable=False),
        sa.Column('parsed_fields', sa.JSON(), nullable=True),
        sa.Column('ingestion_job_id', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['ingestion_job_id'], ['ingestion_jobs.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_events_fingerprint', 'events', ['event_fingerprint'], unique=True)
    op.create_index('ix_events_timestamp', 'events', ['timestamp'])
    op.create_index('ix_events_source_format', 'events', ['source_format'])

    # 4. Detection Rules
    op.create_table(
        'detection_rules',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('rule_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False, server_default='medium'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='enabled'),
        sa.Column('tactic', sa.String(length=64), nullable=False),
        sa.Column('technique_id', sa.String(length=32), nullable=False),
        sa.Column('technique_name', sa.String(length=128), nullable=False),
        sa.Column('window_seconds', sa.Integer(), nullable=False, server_default='300'),
        sa.Column('threshold', sa.Integer(), nullable=False, server_default='5'),
        sa.Column('version', sa.String(length=16), nullable=False, server_default='1.0.0'),
        sa.Column('parameters', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_rules_rule_id', 'detection_rules', ['rule_id'], unique=True)

    # 5. Alerts
    op.create_table(
        'alerts',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('alert_id', sa.String(length=64), nullable=False),
        sa.Column('rule_id', sa.String(length=64), nullable=False),
        sa.Column('rule_name', sa.String(length=128), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('risk_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='new'),
        sa.Column('attack_tactic', sa.String(length=64), nullable=False),
        sa.Column('attack_technique', sa.String(length=32), nullable=False),
        sa.Column('attack_technique_name', sa.String(length=128), nullable=False),
        sa.Column('correlation_key', sa.String(length=128), nullable=True),
        sa.Column('supporting_event_ids', sa.JSON(), nullable=True),
        sa.Column('context_data', sa.JSON(), nullable=True),
        sa.Column('analyst_disposition', sa.String(length=64), nullable=True),
        sa.Column('disposition_notes', sa.Text(), nullable=True),
        sa.Column('assigned_to', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_alerts_alert_id', 'alerts', ['alert_id'], unique=True)

    # 6. Alert Evidence
    op.create_table(
        'alert_evidence',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('alert_id', sa.String(length=64), nullable=False),
        sa.Column('event_id', sa.String(length=64), nullable=False),
        sa.Column('relationship_type', sa.String(length=64), nullable=False, server_default='trigger'),
        sa.Column('evidence_details', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.alert_id']),
        sa.PrimaryKeyConstraint('id'),
    )

    # 7. IOCs
    op.create_table(
        'iocs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('indicator_value', sa.String(length=255), nullable=False),
        sa.Column('indicator_type', sa.String(length=32), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False, server_default='medium'),
        sa.Column('confidence', sa.Integer(), nullable=False, server_default='75'),
        sa.Column('source', sa.String(length=128), nullable=False, server_default='ThreatLens'),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_iocs_val', 'iocs', ['indicator_value'], unique=True)

    # 8. IOC Matches
    op.create_table(
        'ioc_matches',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('ioc_id', sa.Integer(), nullable=False),
        sa.Column('event_id', sa.String(length=64), nullable=False),
        sa.Column('alert_id', sa.String(length=64), nullable=True),
        sa.Column('matched_field', sa.String(length=64), nullable=False),
        sa.Column('matched_value', sa.String(length=255), nullable=False),
        sa.Column('match_context', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['ioc_id'], ['iocs.id']),
        sa.PrimaryKeyConstraint('id'),
    )

    # 9. Campaigns
    op.create_table(
        'campaigns',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('campaign_id', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='active'),
        sa.Column('risk_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('primary_tactic', sa.String(length=64), nullable=False, server_default='Initial Access'),
        sa.Column('primary_technique', sa.String(length=64), nullable=False, server_default='Multiple'),
        sa.Column('common_signals', sa.JSON(), nullable=True),
        sa.Column('correlation_reason', sa.Text(), nullable=False),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_campaigns_id', 'campaigns', ['campaign_id'], unique=True)

    # 10. Campaign Alerts
    op.create_table(
        'campaign_alerts',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('campaign_id', sa.String(length=64), nullable=False),
        sa.Column('alert_id', sa.String(length=64), nullable=False),
        sa.Column('added_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['campaign_id'], ['campaigns.campaign_id']),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.alert_id']),
        sa.PrimaryKeyConstraint('id'),
    )

    # 11. Threat Scores
    op.create_table(
        'threat_scores',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('entity_type', sa.String(length=32), nullable=False),
        sa.Column('entity_id', sa.String(length=64), nullable=False),
        sa.Column('total_score', sa.Float(), nullable=False),
        sa.Column('severity_factor', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('confidence_factor', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('frequency_factor', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('ioc_factor', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('campaign_factor', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('explanation', sa.Text(), nullable=False),
        sa.Column('factor_breakdown', sa.JSON(), nullable=True),
        sa.Column('calculated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )

    # 12. Investigations
    op.create_table(
        'investigations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('inquiry_id', sa.String(length=64), nullable=False),
        sa.Column('alert_id', sa.String(length=64), nullable=True),
        sa.Column('campaign_id', sa.String(length=64), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('question', sa.Text(), nullable=False),
        sa.Column('answer', sa.Text(), nullable=False),
        sa.Column('retrieved_evidence', sa.JSON(), nullable=True),
        sa.Column('citations', sa.JSON(), nullable=True),
        sa.Column('model_used', sa.String(length=64), nullable=False, server_default='deterministic-fallback'),
        sa.Column('is_fallback', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_investigations_inquiry', 'investigations', ['inquiry_id'], unique=True)

    # 13. Playbooks
    op.create_table(
        'playbooks',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('playbook_id', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=128), nullable=False),
        sa.Column('category', sa.String(length=64), nullable=False),
        sa.Column('attack_technique', sa.String(length=32), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('triage_steps', sa.JSON(), nullable=True),
        sa.Column('containment_steps', sa.JSON(), nullable=True),
        sa.Column('remediation_steps', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_playbooks_id', 'playbooks', ['playbook_id'], unique=True)

    # 14. Audit Logs
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('username', sa.String(length=64), nullable=False, server_default='system'),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('resource_type', sa.String(length=64), nullable=False),
        sa.Column('resource_id', sa.String(length=64), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('ip_address', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('playbooks')
    op.drop_table('investigations')
    op.drop_table('threat_scores')
    op.drop_table('campaign_alerts')
    op.drop_table('campaigns')
    op.drop_table('ioc_matches')
    op.drop_table('iocs')
    op.drop_table('alert_evidence')
    op.drop_table('alerts')
    op.drop_table('detection_rules')
    op.drop_table('events')
    op.drop_table('ingestion_jobs')
    op.drop_table('users')

