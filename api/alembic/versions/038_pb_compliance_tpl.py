"""Add playbook kind, profile link, and version for compliance templates.

Revision ID: 038_pb_compliance_tpl
Revises: 037_playbook_platform
Create Date: 2026-08-09
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "038_pb_compliance_tpl"
down_revision: Union[str, None] = "037_playbook_platform"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PLAYBOOK_KIND = sa.Enum("user", "compliance_template", name="playbookkind")


def upgrade() -> None:
    _PLAYBOOK_KIND.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "playbooks",
        sa.Column("kind", _PLAYBOOK_KIND, nullable=False, server_default="user"),
    )
    op.add_column(
        "playbooks",
        sa.Column("profile_id", sa.Integer(), nullable=True),
    )
    op.add_column(
        "playbooks",
        sa.Column("version", sa.String(length=32), nullable=False, server_default="1.0.0"),
    )
    op.create_index("ix_playbooks_kind", "playbooks", ["kind"])
    op.create_index("ix_playbooks_profile_id", "playbooks", ["profile_id"])
    op.create_foreign_key(
        "fk_playbooks_profile_id",
        "playbooks",
        "profiles",
        ["profile_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_playbooks_profile_id", "playbooks", type_="foreignkey")
    op.drop_index("ix_playbooks_profile_id", table_name="playbooks")
    op.drop_index("ix_playbooks_kind", table_name="playbooks")
    op.drop_column("playbooks", "version")
    op.drop_column("playbooks", "profile_id")
    op.drop_column("playbooks", "kind")
    _PLAYBOOK_KIND.drop(op.get_bind(), checkfirst=True)
