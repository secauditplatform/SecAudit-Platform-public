"""DB upsert for compliance playbook templates created from profile packages."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from secaudit_core.base import Base
from secaudit_core.compliance_playbooks import upsert_compliance_playbook_for_profile
from secaudit_core.enums import CategoryType, PlaybookKind
from secaudit_core.models import Category, Playbook, Profile


MINIMAL_PLAYBOOK = """---
- name: Demo compliance
  hosts: all
  tasks:
    - ansible.builtin.debug:
        msg: ok
"""


def _session(tmp_path: Path) -> Session:
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_upsert_compliance_playbook_creates_template(tmp_path: Path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "description.json").write_text(
        json.dumps(
            {
                "profile_name": "Alma Demo",
                                "version": "1.0",
                "compliance_playbook": "Alma_10_compliance.yml",
                "compliance_playbook_version": "1.0",
                "os": {"name": "AlmaLinux", "vendor": "Alma", "version": "10"},
            }
        ),
        encoding="utf-8",
    )
    (package_dir / "Alma_10_compliance.yml").write_text(MINIMAL_PLAYBOOK, encoding="utf-8")

    db = _session(tmp_path)
    category = Category(
        name="Linux Platform",
        slug="linux-platform",
        category_type=CategoryType.OS,
    )
    db.add(category)
    db.flush()
    profile = Profile(
        profile_name="Alma Demo",
        version="1.0.0",
        category_id=category.id,
        package_path=str(package_dir),
    )
    db.add(profile)
    db.flush()

    playbook = upsert_compliance_playbook_for_profile(db, profile, package_dir=package_dir)
    db.commit()

    assert playbook is not None
    assert playbook.kind == PlaybookKind.COMPLIANCE_TEMPLATE
    assert playbook.profile_id == profile.id
    assert playbook.platform == "linux"
    assert playbook.version == "1.0"
    assert "Demo compliance" in playbook.content

    again = upsert_compliance_playbook_for_profile(db, profile, package_dir=package_dir)
    db.commit()
    assert again is not None
    assert again.id == playbook.id
    count = db.execute(
        select(Playbook).where(Playbook.kind == PlaybookKind.COMPLIANCE_TEMPLATE)
    ).scalars().all()
    assert len(count) == 1


def test_upsert_reattaches_orphaned_template_after_profile_rename(tmp_path: Path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "description.json").write_text(
        json.dumps(
            {
                "profile_name": "Astra Linux (Воронеж)",
                                "version": "1.0",
                "compliance_playbook": "AstraVoronej_compliance.yml",
                "compliance_playbook_version": "1.0",
                "os": {"name": "Astra Linux (Voronezh)"},
            }
        ),
        encoding="utf-8",
    )
    (package_dir / "AstraVoronej_compliance.yml").write_text(MINIMAL_PLAYBOOK, encoding="utf-8")

    db = _session(tmp_path)
    category = Category(name="Linux Platform", slug="linux-platform", category_type=CategoryType.OS)
    db.add(category)
    db.flush()
    orphan = Playbook(
        name="Astra Linux (Voronezh) — Compliance",
        content=MINIMAL_PLAYBOOK,
        kind=PlaybookKind.COMPLIANCE_TEMPLATE,
        profile_id=None,
        platform="linux",
    )
    db.add(orphan)
    db.flush()
    orphan_id = orphan.id
    profile = Profile(
        profile_name="Astra Linux (Воронеж)",
        version="1.0",
        category_id=category.id,
        package_path=str(package_dir),
    )
    db.add(profile)
    db.flush()

    playbook = upsert_compliance_playbook_for_profile(db, profile, package_dir=package_dir)
    db.commit()

    assert playbook is not None
    assert playbook.id == orphan_id
    assert playbook.profile_id == profile.id
    rows = db.execute(
        select(Playbook).where(Playbook.kind == PlaybookKind.COMPLIANCE_TEMPLATE)
    ).scalars().all()
    assert len(rows) == 1


def test_dedupe_keeps_distinct_profiles_and_drops_orphans(tmp_path: Path) -> None:
    from secaudit_core.compliance_playbooks import dedupe_orphaned_compliance_templates

    db = _session(tmp_path)
    linux = Category(name="Linux", slug="linux-platform", category_type=CategoryType.OS)
    network = Category(name="Network", slug="network-platform", category_type=CategoryType.NETWORK)
    db.add_all([linux, network])
    db.flush()
    esr = Profile(profile_name="Eltex_ESR", version="1.0", category_id=network.id)
    mes = Profile(profile_name="Eltex_MES", version="1.0", category_id=network.id)
    astra = Profile(
        profile_name="Astra Linux (Воронеж)",
        version="1.0",
        category_id=linux.id,
    )
    db.add_all([esr, mes, astra])
    db.flush()
    db.add_all(
        [
            Playbook(
                name="Eltex — Compliance",
                content=MINIMAL_PLAYBOOK,
                kind=PlaybookKind.COMPLIANCE_TEMPLATE,
                profile_id=esr.id,
                platform="network",
            ),
            Playbook(
                name="Eltex_MES Compliance",
                content=MINIMAL_PLAYBOOK,
                kind=PlaybookKind.COMPLIANCE_TEMPLATE,
                profile_id=mes.id,
                platform="network",
            ),
            Playbook(
                name="Astra Linux (Voronezh) — Compliance",
                content=MINIMAL_PLAYBOOK,
                kind=PlaybookKind.COMPLIANCE_TEMPLATE,
                profile_id=None,
                platform="linux",
            ),
            Playbook(
                name="Astra Linux (Воронеж) Compliance",
                content=MINIMAL_PLAYBOOK,
                kind=PlaybookKind.COMPLIANCE_TEMPLATE,
                profile_id=astra.id,
                platform="linux",
            ),
        ]
    )
    db.flush()

    removed = dedupe_orphaned_compliance_templates(db)
    db.commit()
    assert removed == 1
    names = {
        row.name
        for row in db.execute(
            select(Playbook).where(Playbook.kind == PlaybookKind.COMPLIANCE_TEMPLATE)
        ).scalars()
    }
    assert names == {
        "Eltex — Compliance",
        "Eltex_MES Compliance",
        "Astra Linux (Воронеж) Compliance",
    }


def test_dedupe_matches_latin_orphan_to_cyrillic_label(tmp_path: Path) -> None:
    from secaudit_core.compliance_playbooks import dedupe_orphaned_compliance_templates

    db = _session(tmp_path)
    linux = Category(name="Linux", slug="linux-platform", category_type=CategoryType.OS)
    db.add(linux)
    db.flush()
    astra = Profile(
        profile_name="Astra Linux (Воронеж)",
        version="1.0",
        category_id=linux.id,
    )
    db.add(astra)
    db.flush()
    db.add_all(
        [
            Playbook(
                name="Astra Linux (Voronezh) — Compliance",
                content=MINIMAL_PLAYBOOK,
                kind=PlaybookKind.COMPLIANCE_TEMPLATE,
                profile_id=None,
                platform="linux",
            ),
            Playbook(
                name="Astra Linux (Воронеж) Compliance",
                content=MINIMAL_PLAYBOOK,
                kind=PlaybookKind.COMPLIANCE_TEMPLATE,
                profile_id=astra.id,
                platform="linux",
            ),
        ]
    )
    db.flush()

    removed = dedupe_orphaned_compliance_templates(db)
    db.commit()
    assert removed == 1
    remaining = db.execute(
        select(Playbook).where(Playbook.kind == PlaybookKind.COMPLIANCE_TEMPLATE)
    ).scalars().all()
    assert len(remaining) == 1
    assert remaining[0].profile_id == astra.id


def test_upsert_reattaches_latin_orphan_when_label_is_cyrillic(tmp_path: Path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "description.json").write_text(
        json.dumps(
            {
                "profile_name": "Astra Linux (Воронеж)",
                                "version": "1.0",
                "compliance_playbook": "AstraVoronej_compliance.yml",
                "compliance_playbook_version": "1.0",
                "os": {"name": "Astra Linux (Voronezh)"},
            }
        ),
        encoding="utf-8",
    )
    (package_dir / "AstraVoronej_compliance.yml").write_text(MINIMAL_PLAYBOOK, encoding="utf-8")

    db = _session(tmp_path)
    category = Category(name="Linux Platform", slug="linux-platform", category_type=CategoryType.OS)
    db.add(category)
    db.flush()
    orphan = Playbook(
        name="Astra Linux (Voronezh) — Compliance",
        content=MINIMAL_PLAYBOOK,
        kind=PlaybookKind.COMPLIANCE_TEMPLATE,
        profile_id=None,
        platform="linux",
    )
    db.add(orphan)
    db.flush()
    orphan_id = orphan.id
    profile = Profile(
        profile_name="Astra Linux (Воронеж)",
        version="1.0",
        category_id=category.id,
        package_path=str(package_dir),
    )
    db.add(profile)
    db.flush()

    playbook = upsert_compliance_playbook_for_profile(db, profile, package_dir=package_dir)
    db.commit()

    assert playbook is not None
    assert playbook.id == orphan_id
    assert playbook.profile_id == profile.id
    rows = db.execute(
        select(Playbook).where(Playbook.kind == PlaybookKind.COMPLIANCE_TEMPLATE)
    ).scalars().all()
    assert len(rows) == 1

