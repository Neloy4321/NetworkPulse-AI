"""64-bit PostgreSQL flow counters and query-oriented indexes.

Revision ID: 0002_counter_integrity
Revises: 0001_legacy_baseline
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_counter_integrity"
down_revision = "0001_legacy_baseline"
branch_labels = None
depends_on = None


def upgrade():
    if op.get_bind().dialect.name == "postgresql":
        for col in ("orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"):
            op.alter_column("network_events", col, existing_type=sa.Integer(),
                            type_=sa.BigInteger(), existing_nullable=True)
    # SQLite INTEGER is already signed 64-bit, and no table rebuild is needed.
    op.create_index("idx_flow_anomalous_time", "network_events", ["anomalous", "timestamp"])
    op.create_index("idx_flow_src_timestamp", "network_events", ["src_ip", "timestamp"])
    op.create_index("idx_alert_status_created", "alerts", ["status", "created_at"])


def downgrade():
    op.drop_index("idx_alert_status_created", table_name="alerts")
    op.drop_index("idx_flow_src_timestamp", table_name="network_events")
    op.drop_index("idx_flow_anomalous_time", table_name="network_events")
    if op.get_bind().dialect.name == "postgresql":
        raise NotImplementedError("Counter narrowing can lose data; restore an earlier backup instead")
