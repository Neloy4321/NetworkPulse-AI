"""Durable source/window behavior findings and attributed case history.

Revision ID: 0004_behavior_findings
Revises: 0003_soc_accountability
"""
import sqlalchemy as sa
from alembic import op

revision = "0004_behavior_findings"
down_revision = "0003_soc_accountability"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "behavior_findings",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("source_ip", sa.String(45), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_minutes", sa.Integer(), nullable=False),
        sa.Column("patterns", sa.JSON(), nullable=False),
        sa.Column("flow_count", sa.Integer(), nullable=False),
        sa.Column("destination_ports", sa.Integer(), nullable=False),
        sa.Column("destination_hosts", sa.Integer(), nullable=False),
        sa.Column("flagged_flows", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("assigned_to", sa.String(150)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_behavior_findings_source_ip", "behavior_findings", ["source_ip"])
    op.create_index("idx_behavior_source_window", "behavior_findings", ["source_ip", "window_start"])
    op.create_index("idx_behavior_status_window", "behavior_findings", ["status", "window_start"])
    op.create_table(
        "behavior_finding_audit",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finding_id", sa.String(32), sa.ForeignKey("behavior_findings.id"), nullable=False),
        sa.Column("actor", sa.String(150), nullable=False),
        sa.Column("old_status", sa.String(20), nullable=False),
        sa.Column("new_status", sa.String(20), nullable=False),
        sa.Column("old_assignee", sa.String(150)),
        sa.Column("new_assignee", sa.String(150)),
        sa.Column("note", sa.String(1500), nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_behavior_finding_audit_finding_id",
                    "behavior_finding_audit", ["finding_id"])


def downgrade():
    # Operator must explicitly choose downgrade; previous flow/ML alert tables
    # remain intact but behavior-case history will be lost.
    op.drop_index("ix_behavior_finding_audit_finding_id", "behavior_finding_audit")
    op.drop_table("behavior_finding_audit")
    op.drop_index("idx_behavior_status_window", "behavior_findings")
    op.drop_index("idx_behavior_source_window", "behavior_findings")
    op.drop_index("ix_behavior_findings_source_ip", "behavior_findings")
    op.drop_table("behavior_findings")
