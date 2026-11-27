"""Asset identities and IPv6-ready directory endpoints (schema only).

Revision ID: 085_asset_identity
Revises: 084_remediation_rule_results
Create Date: 2026-11-14
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "085_asset_identity"
down_revision = "084_remediation_rule_results"
branch_labels = None
depends_on = None

_ASSET_KIND = postgresql.ENUM(
    "ssh_fingerprint",
    "winrm_thumbprint",
    "snmp_serial",
    "machine_id",
    "mac",
    name="assetidentitykind",
    create_type=False,
)


def upgrade() -> None:
    _ASSET_KIND.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "asset_identities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("host_id", sa.Integer(), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", _ASSET_KIND, nullable=False),
        sa.Column("value", sa.String(length=256), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint("kind", "value", name="uq_asset_identity_kind_value"),
    )
    op.create_index("ix_asset_identities_host_id", "asset_identities", ["host_id"])
    # Backfill SSH fingerprints already stored on hosts.
    op.execute(
        sa.text(
            """
            INSERT INTO asset_identities (host_id, kind, value)
            SELECT id, 'ssh_fingerprint', lower(ssh_host_key_fingerprint)
            FROM hosts
            WHERE ssh_host_key_fingerprint IS NOT NULL
              AND btrim(ssh_host_key_fingerprint) <> ''
            ON CONFLICT ON CONSTRAINT uq_asset_identity_kind_value DO NOTHING
            """
        )
    )


def downgrade() -> None:
    op.drop_index("ix_asset_identities_host_id", table_name="asset_identities")
    op.drop_table("asset_identities")
    _ASSET_KIND.drop(op.get_bind(), checkfirst=True)
