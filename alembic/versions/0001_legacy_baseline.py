"""Recreate the NetworkPulse v0.1 schema for fresh installations.

Revision ID: 0001_legacy_baseline
Revises:
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_legacy_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "network_events",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(30), nullable=False),
        sa.Column("uid", sa.String(160), nullable=True),
        sa.Column("src_ip", sa.String(45), nullable=False),
        sa.Column("dst_ip", sa.String(45)),
        sa.Column("src_port", sa.Integer()),
        sa.Column("dst_port", sa.Integer()),
        sa.Column("proto", sa.String(12)),
        sa.Column("duration", sa.Float()),
        sa.Column("orig_bytes", sa.Integer()),
        sa.Column("resp_bytes", sa.Integer()),
        sa.Column("orig_pkts", sa.Integer()),
        sa.Column("resp_pkts", sa.Integer()),
        sa.Column("conn_state", sa.String(24)),
        sa.Column("anomaly_score", sa.Float()),
        sa.Column("risk", sa.Integer()),
        sa.Column("anomalous", sa.Boolean()),
        sa.Column("ingested_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_network_events_timestamp", "network_events", ["timestamp"])
    op.create_index("ix_network_events_src_ip", "network_events", ["src_ip"])
    op.create_index("ix_network_events_anomalous", "network_events", ["anomalous"])
    op.create_index("idx_flow_timestamp_src", "network_events", ["timestamp", "src_ip"])
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("event_id", sa.String(32), sa.ForeignKey("network_events.id"), unique=True),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("reasons", sa.JSON()),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_table(
        "alert_audit",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id"), nullable=False),
        sa.Column("old_status", sa.String(20)),
        sa.Column("new_status", sa.String(20)),
        sa.Column("note", sa.String(1500)),
        sa.Column("changed_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_alert_audit_alert_id", "alert_audit", ["alert_id"])


def downgrade():
    op.drop_table("alert_audit")
    op.drop_table("alerts")
    op.drop_table("network_events")
