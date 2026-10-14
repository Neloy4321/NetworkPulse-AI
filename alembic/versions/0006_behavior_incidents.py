"""Durable cross-window incident evidence and attributed SOC case review.

Revision ID: 0006_behavior_incidents
Revises: 0005_mlops_drift_runs
"""
import sqlalchemy as sa
from alembic import op

revision = "0006_behavior_incidents"
down_revision = "0005_mlops_drift_runs"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "behavior_incidents",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("source_ip", sa.String(45), nullable=False),
        sa.Column("hour_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_count", sa.Integer(), nullable=False),
        sa.Column("finding_ids", sa.JSON(), nullable=False),
        sa.Column("patterns", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("total_flows", sa.Integer(), nullable=False),
        sa.Column("flagged_flows", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("assigned_to", sa.String(150)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_incident_source_hour", "behavior_incidents",
                    ["source_ip", "hour_start"])
    op.create_index("idx_incident_status_hour", "behavior_incidents",
                    ["status", "hour_start"])
    op.create_table(
        "behavior_incident_audit",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.String(32),
                  sa.ForeignKey("behavior_incidents.id"), nullable=False),
        sa.Column("actor", sa.String(150), nullable=False),
        sa.Column("old_status", sa.String(20), nullable=False),
        sa.Column("new_status", sa.String(20), nullable=False),
        sa.Column("old_assignee", sa.String(150)),
        sa.Column("new_assignee", sa.String(150)),
        sa.Column("note", sa.String(1500), nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_incident_audit_case", "behavior_incident_audit",
                    ["incident_id", "changed_at"])


def downgrade():
    # A downgrade loses incident evidence and audit, not existing findings/flows.
    op.drop_index("idx_incident_audit_case", table_name="behavior_incident_audit")
    op.drop_table("behavior_incident_audit")
    op.drop_index("idx_incident_status_hour", table_name="behavior_incidents")
    op.drop_index("idx_incident_source_hour", table_name="behavior_incidents")
    op.drop_table("behavior_incidents")
