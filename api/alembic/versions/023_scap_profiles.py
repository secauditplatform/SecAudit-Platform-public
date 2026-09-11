"""SCAP profile metadata on standards.

Revision ID: 023_scap_profiles
Revises: 022_job_webhooks
Create Date: 2026-07-13
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "023_scap_profiles"
down_revision: Union[str, None] = "022_job_webhooks"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("standards", sa.Column("profile_family", sa.String(length=32), nullable=True))
    op.add_column("standards", sa.Column("scap_profile_id", sa.String(length=256), nullable=True))
    op.add_column("standards", sa.Column("profile_title", sa.String(length=512), nullable=True))
    op.add_column("standards", sa.Column("benchmark_ref", sa.String(length=512), nullable=True))


def downgrade() -> None:
    op.drop_column("standards", "benchmark_ref")
    op.drop_column("standards", "profile_title")
    op.drop_column("standards", "scap_profile_id")
    op.drop_column("standards", "profile_family")
