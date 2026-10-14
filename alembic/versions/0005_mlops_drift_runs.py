"""Operational ML drift evidence: immutable model/window/input-snapshot reports.

Revision ID: 0005_mlops_drift_runs
Revises: 0004_behavior_findings
"""
import sqlalchemy as sa
from alembic import op

revision = "0005_mlops_drift_runs"
down_revision = "0004_behavior_findings"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "mlops_drift_runs",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("model_sha256", sa.String(64), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("input_fingerprint", sa.String(64), nullable=False),
        sa.Column("flow_count", sa.Integer(), nullable=False),
        sa.Column("flagged_flows", sa.Integer(), nullable=False),
        sa.Column("drift_status", sa.String(20), nullable=False),
        sa.Column("alert_budget_exceeded", sa.Boolean(), nullable=False),
        sa.Column("worst_psi", sa.Float(), nullable=False),
        sa.Column("report", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_mlops_drift_end", "mlops_drift_runs", ["window_end"])
    op.create_index("idx_mlops_drift_status_end", "mlops_drift_runs",
                    ["drift_status", "window_end"])


def downgrade():
    op.drop_index("idx_mlops_drift_status_end", table_name="mlops_drift_runs")
    op.drop_index("idx_mlops_drift_end", table_name="mlops_drift_runs")
    op.drop_table("mlops_drift_runs")
