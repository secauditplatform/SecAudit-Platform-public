"""AuditFlow extra app profiles, SSH host-key pinning fields.

Revision ID: 040_audit_flow_quality
Revises: 039_audit_flow
Create Date: 2026-08-14
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "040_audit_flow_quality"
down_revision: Union[str, None] = "039_audit_flow"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("audit_flow_hosts", sa.Column("extra_profiles_json", sa.JSON(), nullable=True))
    op.add_column("audit_flow_hosts", sa.Column("extra_runs_json", sa.JSON(), nullable=True))
    op.add_column("audit_flow_hosts", sa.Column("ssh_host_key_fingerprint", sa.String(length=128), nullable=True))
    op.add_column("audit_flow_hosts", sa.Column("ssh_known_hosts_entry", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("audit_flow_hosts", "ssh_known_hosts_entry")
    op.drop_column("audit_flow_hosts", "ssh_host_key_fingerprint")
    op.drop_column("audit_flow_hosts", "extra_runs_json")
    op.drop_column("audit_flow_hosts", "extra_profiles_json")
