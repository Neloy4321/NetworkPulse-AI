"""SOC ownership and attributed alert history.

Revision ID: 0003_soc_accountability
Revises: 0002_counter_integrity
"""
import sqlalchemy as sa
from alembic import op

revision = '0003_soc_accountability'
down_revision = '0002_counter_integrity'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('alerts', sa.Column('assigned_to', sa.String(150), nullable=True))
    op.add_column('alert_audit', sa.Column('actor', sa.String(150), nullable=True))
    op.create_table('alert_notes',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('alert_id', sa.Integer(), sa.ForeignKey('alerts.id'), nullable=False),
        sa.Column('actor', sa.String(150), nullable=False),
        sa.Column('note', sa.String(1500), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('idx_alert_notes_alert_date', 'alert_notes', ['alert_id', 'created_at'])
    op.create_index('idx_alert_assignee', 'alerts', ['assigned_to'])


def downgrade():
    op.drop_index('idx_alert_assignee', table_name='alerts')
    op.drop_index('idx_alert_notes_alert_date', table_name='alert_notes')
    op.drop_table('alert_notes')
    op.drop_column('alert_audit', 'actor')
    op.drop_column('alerts', 'assigned_to')
