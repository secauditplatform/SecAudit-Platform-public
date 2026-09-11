"""Upgrade legacy connectivity-check playbooks to use win_ping on WinRM hosts.

Revision ID: 048_connectivity_playbook_winrm
Revises: 047_credential_service_auth
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

from secaudit_core.connectivity_playbook import (
    CONNECTIVITY_CHECK_CONTENT,
    is_legacy_connectivity_check_content,
)

revision: str = "048_connectivity_playbook_winrm"
down_revision: Union[str, None] = "047_credential_service_auth"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT id, content FROM playbooks")).fetchall()
    for row in rows:
        if not is_legacy_connectivity_check_content(row.content):
            continue
        conn.execute(
            sa.text(
                """
                UPDATE playbooks
                SET content = :content, updated_at = CURRENT_TIMESTAMP
                WHERE id = :id
                """
            ),
            {"content": CONNECTIVITY_CHECK_CONTENT, "id": row.id},
        )


def downgrade() -> None:
    legacy_content = """---
- name: SecAudit connectivity check
  hosts: all
  gather_facts: false
  tasks:
    - name: Ping target
      ansible.builtin.ping:
"""
    conn = op.get_bind()
    rows = conn.execute(
        sa.text("SELECT id, content FROM playbooks WHERE content = :content"),
        {"content": CONNECTIVITY_CHECK_CONTENT},
    ).fetchall()
    for row in rows:
        conn.execute(
            sa.text(
                """
                UPDATE playbooks
                SET content = :content, updated_at = CURRENT_TIMESTAMP
                WHERE id = :id
                """
            ),
            {"content": legacy_content, "id": row.id},
        )
