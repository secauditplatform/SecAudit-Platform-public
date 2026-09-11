import json
from pathlib import Path

import pytest

from tests.repo_paths import profiles_root

from app.models import CheckStatus
from app.services.interpreter import (
    REMEDIATION_SCRIPT_MARKER,
    apply_interpreter_rules,
    discover_remediation_scripts,
    infer_category_from_package_dir,
    infer_category_slug,
    load_profile_package,
    read_package_text_file,
    validate_profile_package,
)
from secaudit_core.interpreter import apply_interpreter_rules as core_apply_interpreter_rules

LINUX_PLATFORM_ROOT = profiles_root() / "Linux Platform"


def test_apply_interpreter_rules_extracts_status_and_message():
    output = "RULE1= PASS: SSH root login disabled\nRULE2= FAIL: Password auth enabled"
    rules = [
        {"regex": r"(RULE\d+=\s*PASS:.*)", "tech_name": "RULE1"},
        {"regex": r"(RULE\d+=\s*FAIL:.*)", "tech_name": "RULE2"},
    ]

    results = apply_interpreter_rules(output, rules)

    assert len(results) == 2
    assert results[0]["tech_name"] == "RULE1"
    assert results[0]["status"] == CheckStatus.PASS
    assert "SSH root login disabled" in results[0]["message"]
    assert results[1]["status"] == CheckStatus.FAIL


def test_apply_interpreter_rules_skips_rules_without_tech_name():
    output = "line with PASS: ok"
    rules = [{"regex": r"(PASS: ok)", "tech_name": ""}]

    assert apply_interpreter_rules(output, rules) == []
    assert core_apply_interpreter_rules(output, rules) == []


def test_apply_interpreter_rules_shared_with_core():
    output = "RULE1= PASS: shared"
    rules = [{"regex": r"(RULE\d+=\s*PASS:.*)", "tech_name": "RULE1"}]
    assert apply_interpreter_rules(output, rules) == core_apply_interpreter_rules(output, rules)


def test_discover_remediation_scripts_finds_marked_files(tmp_path: Path):
    (tmp_path / "check_audit.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    remediation = tmp_path / f"fix{REMEDIATION_SCRIPT_MARKER}.sh"
    remediation.write_text("#!/bin/sh\necho fix\n", encoding="utf-8")

    scripts = discover_remediation_scripts(tmp_path)

    assert len(scripts) == 1
    assert scripts[0]["name"] == remediation.stem
    assert scripts[0]["script_file"] == remediation.name
    assert scripts[0]["type"] == "SSH"


def test_discover_remediation_scripts_in_scripts_subdir(tmp_path: Path):
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    script = scripts_dir / f"patch{REMEDIATION_SCRIPT_MARKER}.py"
    script.write_text("print('ok')\n", encoding="utf-8")

    found = discover_remediation_scripts(tmp_path)

    assert len(found) == 1
    assert found[0]["type"] == "PYTHON"
    assert found[0]["script_file"] == "scripts/patch_remediation.py"


def test_infer_category_slug_prefers_os_over_software():
    os_meta = {"name": "Debian Linux", "vendor": "Debian Project"}
    software_meta = {"name": "Debian Linux", "category": "Операционнные системы"}
    assert infer_category_slug(None, os_meta, software_meta) == "linux-platform"


def test_infer_category_slug_uses_explicit_tree_path_override():
    # tree_path may still be passed explicitly; packages no longer load standard-meta.json
    assert infer_category_slug("OS;LINUX", None, {"name": "svc"}) == "linux-platform"


def test_infer_category_slug_software_os_category_without_os_meta():
    software_meta = {"name": "Debian Linux", "vendor": "Debian", "category": "Операционнные системы"}
    assert infer_category_slug(None, None, software_meta) == "linux-platform"


def test_infer_category_from_package_dir_debian13(tmp_path: Path):
    (tmp_path / "description.json").write_text(
        json.dumps(
            {
                "profile_name": "Debian 13",
                "os": {"name": "Debian Linux"},
                "software": {"name": "Debian Linux", "category": "Операционнные системы"},
            }
        ),
        encoding="utf-8",
    )
    # Stale meta files must be ignored if present
    (tmp_path / "standard-meta.json").write_text(
        '{"tree_path":"NETWORK;CISCO"}',
        encoding="utf-8",
    )
    (tmp_path / "rule_types.json").write_text("[]", encoding="utf-8")
    assert infer_category_from_package_dir(tmp_path) == "linux-platform"


def test_read_package_text_file_falls_back_to_cp1252(tmp_path: Path):
    script = tmp_path / "fix_remediation.sh"
    script.write_bytes(b"#!/bin/sh\n# remediation \x97 ok\n")
    content = read_package_text_file(script)
    assert "remediation" in content
    assert "ok" in content


@pytest.mark.parametrize(
    "relative_dir",
    [
        "AlmaLInux9_CRE_NUP(1.3.0)_AI/AlmaLInux9_CRE_AI",
        "Debian_13_CRE_NUP(1.3.0)_AI/Debian_13_CRE_AI",
        "RHEL9_CRE_NUP_AI/RHEL9_CRE_AI",
    ],
)
def test_bundled_linux_platform_description_json_loads(relative_dir: str) -> None:
    package_dir = LINUX_PLATFORM_ROOT / relative_dir
    if not package_dir.is_dir():
        pytest.skip(f"Bundled package not present: {relative_dir}")

    assert (package_dir / "description.json").is_file()
    assert not (package_dir / "os.json").is_file()
    assert not (package_dir / "software.json").is_file()

    validate_profile_package(package_dir)
    loaded = load_profile_package(package_dir)
    assert loaded["category_slug"] == "linux-platform"
    assert isinstance(loaded["profile"]["os"], dict)
    assert loaded["profile"]["profile_name"]
    assert loaded["scripts"]
