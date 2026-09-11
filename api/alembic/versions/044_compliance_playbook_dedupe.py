"""Remove duplicate compliance playbooks left after profile tech_name changes.

Revision ID: 044_compliance_playbook_dedupe
Revises: 043_playbook_version_1_0
Create Date: 2026-08-20
"""

from __future__ import annotations

import re
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "044_compliance_playbook_dedupe"
down_revision: Union[str, None] = "043_playbook_version_1_0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COMPLIANCE_SUFFIX_RE = re.compile(r"\s*[—–-]\s*Compliance\s*$|\s+Compliance\s*$", re.IGNORECASE)
_CYR_TO_LATIN = (
    ("воронеж", "voronezh"),
    ("орёл", "orel"),
    ("орел", "orel"),
    ("смоленск", "smolensk"),
)


def _norm(value: str | None) -> str:
    cleaned = _COMPLIANCE_SUFFIX_RE.sub("", str(value or "")).strip()
    folded = " ".join(cleaned.casefold().split())
    for cyrillic, latin in _CYR_TO_LATIN:
        folded = folded.replace(cyrillic, latin)
    return folded


def _keys(*parts: str | None) -> set[str]:
    return {key for part in parts if (key := _norm(part))}


def _root(parent: dict[str, str], key: str) -> str:
    parent.setdefault(key, key)
    while parent[key] != key:
        parent[key] = parent[parent[key]]
        key = parent[key]
    return key


def upgrade() -> None:
    conn = op.get_bind()
    rows = conn.execute(
        sa.text(
            """
            SELECT p.id, p.name, p.profile_id, pr.label, pr.tech_name
            FROM playbooks p
            LEFT JOIN profiles pr ON pr.id = p.profile_id
            WHERE p.kind = 'compliance_template'
            """
        )
    ).fetchall()

    parent: dict[str, str] = {}
    membership: list[tuple[object, set[str]]] = []
    for row in rows:
        keys = _keys(row.label, row.tech_name, row.name)
        if not keys:
            continue
        iterator = iter(keys)
        root = _root(parent, next(iterator))
        for key in iterator:
            other = _root(parent, key)
            if other != root:
                parent[other] = root
        membership.append((row, keys))

    grouped: dict[str, list] = {}
    for row, keys in membership:
        grouped.setdefault(_root(parent, next(iter(keys))), []).append(row)

    to_delete: list[int] = []
    for items in grouped.values():
        linked = [item for item in items if item.profile_id is not None]
        orphans = [item for item in items if item.profile_id is None]
        seen_profiles: set[int] = set()
        for item in sorted(linked, key=lambda row: row.id):
            if item.profile_id in seen_profiles:
                to_delete.append(item.id)
            else:
                seen_profiles.add(item.profile_id)
        if linked:
            to_delete.extend(item.id for item in orphans)

    if to_delete:
        for playbook_id in to_delete:
            conn.execute(
                sa.text("UPDATE jobs SET playbook_id = NULL WHERE playbook_id = :id"),
                {"id": playbook_id},
            )
            conn.execute(sa.text("DELETE FROM playbooks WHERE id = :id"), {"id": playbook_id})

    op.create_index(
        "uq_playbooks_compliance_profile",
        "playbooks",
        ["profile_id"],
        unique=True,
        postgresql_where=sa.text("kind = 'compliance_template' AND profile_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_playbooks_compliance_profile", table_name="playbooks")
