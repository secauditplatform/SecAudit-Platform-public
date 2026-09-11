"""Tests for SCAP / XCCDF parse and SecAudit package materialization."""

from pathlib import Path
import zipfile

import pytest

from app.services.interpreter import (
    discover_check_scripts,
    load_profile_package,
    load_profile_rules_metadata,
    validate_profile_package,
)
from app.services.scap import (
    convert_oval_package_dir,
    detect_package_format,
    materialize_xccdf_package,
    parse_oval_xml,
    parse_xccdf_profiles,
    parse_xccdf_xml,
    prepare_upload_package,
)
from secaudit_core.oscap import resolve_oval_path, resolve_scap_content_files, resolve_scap_profile_id

SAMPLE_XCCDF = b"""<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.cisecurity.benchmarks_benchmark_Ubuntu_22">
  <title>CIS Ubuntu Linux 22.04 LTS Benchmark</title>
  <description>Sample XCCDF for SecAudit import tests</description>
  <version>2.0.0</version>
  <platform idref="cpe:/o:canonical:ubuntu_linux:22.04"/>
  <Group id="xccdf_org.cisecurity.benchmarks_group_1">
    <title>Filesystem</title>
    <Rule id="xccdf_org.cisecurity.benchmarks_rule_1.1.1.1" severity="high" selected="true">
      <title>Ensure cramfs is disabled</title>
      <description>Disable the cramfs filesystem module.</description>
      <fix system="urn:xccdf:fix:script:sh">
        <fixtext>echo fix-cramfs</fixtext>
      </fix>
    </Rule>
    <Rule id="xccdf_org.cisecurity.benchmarks_rule_1.1.1.2" severity="medium" selected="true">
      <title>Ensure freevxfs is disabled</title>
      <description>Disable freevxfs.</description>
      <check system="http://open-scap.org/page/SCE">
        <check-content>#!/bin/bash
exit 0
</check-content>
      </check>
    </Rule>
  </Group>
</Benchmark>
"""

SAMPLE_XCCDF_WITH_PROFILES = SAMPLE_XCCDF.replace(
    b"</version>",
    b"""</version>
  <Profile id="xccdf_org.cisecurity.benchmarks_profile_Level_1">
    <title>CIS Level 1</title>
    <description>Level 1 profile</description>
  </Profile>
  <Profile id="xccdf_org.cisecurity.benchmarks_profile_Level_2">
    <title>CIS Level 2</title>
  </Profile>""",
)

OVAL_ONLY_EMPTY = b"""<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <generator><schema_version>5.11</schema_version></generator>
  <definitions/>
</oval_definitions>
"""

OVAL_WITH_DEFS = b"""<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <generator><schema_version>5.11</schema_version></generator>
  <definitions>
    <definition id="oval:com.example:def:1" version="1" class="compliance">
      <metadata>
        <title>Ensure package foo is installed</title>
        <description>Package foo must be present.</description>
      </metadata>
    </definition>
    <definition id="oval:com.example:def:2" version="1" class="vulnerability">
      <metadata>
        <title>CVE-2026-0001 patched</title>
        <description>Kernel is patched.</description>
      </metadata>
    </definition>
  </definitions>
</oval_definitions>
"""

XCCDF_WITH_OVAL_REF = b"""<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_com.example_benchmark_ref">
  <title>Benchmark referencing external OVAL</title>
  <version>1.0.0</version>
  <Rule id="xccdf_com.example_rule_1" severity="medium" selected="true">
    <title>Ensure package foo is installed</title>
    <description>Checked via OVAL.</description>
    <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
      <check-content-ref href="example-oval.xml" name="oval:com.example:def:1"/>
    </check>
  </Rule>
</Benchmark>
"""

DATASTREAM = b"""<?xml version="1.0" encoding="UTF-8"?>
<ds:data-stream-collection xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2"
    xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" id="scap_ds_collection">
  <ds:data-stream id="scap_ds">
    <ds:checklists>
      <ds:component-ref id="scap_cref_xccdf"/>
    </ds:checklists>
  </ds:data-stream>
  <ds:component id="scap_comp_xccdf">
    <xccdf:Benchmark id="xccdf_com.example_benchmark_ds">
      <xccdf:title>Datastream Benchmark</xccdf:title>
      <xccdf:version>1.0.0</xccdf:version>
      <xccdf:Rule id="xccdf_com.example_rule_ds_1" severity="low" selected="true">
        <xccdf:title>Datastream rule</xccdf:title>
        <xccdf:description>desc</xccdf:description>
      </xccdf:Rule>
    </xccdf:Benchmark>
  </ds:component>
</ds:data-stream-collection>
"""


def test_parse_xccdf_maps_rules_and_severity():
    benchmark = parse_xccdf_xml(SAMPLE_XCCDF)
    assert benchmark.benchmark_id.startswith("xccdf_org.cisecurity")
    assert "Ubuntu" in benchmark.title
    assert benchmark.version == "2.0.0"
    assert len(benchmark.rules) == 2
    assert benchmark.rules[0].rule_id.endswith("1.1.1.1")
    assert benchmark.rules[0].severity == "HIGH"
    assert benchmark.rules[0].fix_shell == "echo fix-cramfs"
    assert benchmark.rules[1].check_shell is not None
    assert "exit 0" in benchmark.rules[1].check_shell


def test_parse_xccdf_rejects_invalid_xml():
    with pytest.raises(ValueError, match="Invalid XCCDF XML"):
        parse_xccdf_xml(b"<Benchmark><unclosed>")


def test_parse_xccdf_rejects_non_benchmark():
    with pytest.raises(ValueError, match="Benchmark"):
        parse_xccdf_xml(b'<?xml version="1.0"?><Root><item/></Root>')


def test_materialize_xccdf_package_is_valid_secaudit_package(tmp_path: Path):
    benchmark = parse_xccdf_xml(SAMPLE_XCCDF)
    package_dir = materialize_xccdf_package(benchmark, tmp_path / "pkg", xccdf_bytes=SAMPLE_XCCDF)

    validate_profile_package(package_dir)
    loaded = load_profile_package(package_dir)
    assert loaded["profile"]["source_format"] == "xccdf"
    assert loaded["profile"]["profile_name"]
    assert len(loaded["scripts"]) == 1

    rules = load_profile_rules_metadata(package_dir)
    assert len(rules) == 2
    assert rules[0]["scap_rule_id"].endswith("1.1.1.1")
    assert rules[0]["criticality"] == "HIGH"

    scripts = discover_check_scripts(package_dir, loaded["profile"])
    assert len(scripts) == 1
    assert (package_dir / scripts[0]["script_file"]).is_file()
    script_text = (package_dir / scripts[0]["script_file"]).read_text(encoding="utf-8")
    assert "oscap xccdf eval" in script_text
    assert (package_dir / "scap_benchmark.xml").is_file()

    remediations = loaded["remediation_scripts"]
    assert len(remediations) == 2
    assert {item["type"] for item in remediations} == {"SSH", "ANSIBLE"}
    assert any("_remediation" in item["name"] for item in remediations)

    rem_sh = next(package_dir / item["script_file"] for item in remediations if item["type"] == "SSH")
    rem_text = rem_sh.read_text(encoding="utf-8")
    assert "fix-cramfs" in rem_text
    # Rule without fixtext still appears honestly (template or UNSUPPORTED), not omitted.
    assert "1.1.1.2" in rem_text or "freevxfs" in rem_text.lower() or "UNSUPPORTED" in rem_text


def test_materialize_uses_fixtext_and_templates(tmp_path: Path):
    """fixtext → real shell fix; no fixtext → template or explicit UNSUPPORTED (not silent skip-as-pass)."""
    from app.services.scap_remediation import plan_rule_remediation, XccdfFix

    with_fix = plan_rule_remediation(
        rule_id="rule_with_fix",
        title="Ensure cramfs is disabled",
        description="",
        mnemonic="RULE1",
        fixes=[XccdfFix(system="urn:xccdf:fix:script:sh", text="echo fix-cramfs")],
    )
    assert with_fix.kind == "fixtext_shell"
    assert any("fix-cramfs" in line for line in with_fix.shell_lines)
    assert any("PASS:" in line for line in with_fix.shell_lines)

    templated = plan_rule_remediation(
        rule_id="rule_module",
        title="Ensure freevxfs is disabled",
        description="Disable the freevxfs filesystem module.",
        mnemonic="RULE2",
        fixes=[],
    )
    assert templated.kind == "template_kernel_module"
    assert any("freevxfs" in line for line in templated.shell_lines)
    assert not any("silent" in line.lower() for line in templated.shell_lines)

    unsupported = plan_rule_remediation(
        rule_id="rule_obscure",
        title="Ensure proprietary widget flux capacitor calibrated",
        description="No common CIS pattern here.",
        mnemonic="RULE3",
        fixes=[],
    )
    assert unsupported.kind == "unsupported"
    joined = "\n".join(unsupported.shell_lines)
    assert "UNSUPPORTED" in joined
    assert "SKIP:" in joined
    assert "PASS:" not in joined


def test_materialize_ansible_fixtext(tmp_path: Path):
    xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_ansible_bench">
  <title>Ansible fix bench</title>
  <version>1.0.0</version>
  <Rule id="xccdf_rule_pkg" severity="medium" selected="true">
    <title>Ensure package audit is installed</title>
    <description>Install audit package.</description>
    <fix system="urn:xccdf:fix:ansible">
      <fixtext>- name: Install audit
  ansible.builtin.package:
    name: audit
    state: present
</fixtext>
    </fix>
  </Rule>
</Benchmark>
"""
    benchmark = parse_xccdf_xml(xml)
    package_dir = materialize_xccdf_package(benchmark, tmp_path / "pkg", xccdf_bytes=xml)
    remediations = load_profile_package(package_dir)["remediation_scripts"]
    ansible = next(item for item in remediations if item["type"] == "ANSIBLE")
    playbook = (package_dir / ansible["script_file"]).read_text(encoding="utf-8")
    assert "hosts: all" in playbook
    assert "audit" in playbook
    assert "SecAudit SCAP remediation" in playbook


def test_detect_custom_vs_xccdf(tmp_path: Path):
    custom = tmp_path / "custom"
    custom.mkdir()
    (custom / "description.json").write_text('{"profile_name":"demo"}', encoding="utf-8")
    assert detect_package_format(custom) == "custom"

    xccdf_dir = tmp_path / "xccdf"
    xccdf_dir.mkdir()
    (xccdf_dir / "bench.xml").write_bytes(SAMPLE_XCCDF)
    assert detect_package_format(xccdf_dir) == "xccdf"


def test_oval_only_detected_as_oval(tmp_path: Path):
    oval_dir = tmp_path / "oval"
    oval_dir.mkdir()
    (oval_dir / "defs.xml").write_bytes(OVAL_WITH_DEFS)
    assert detect_package_format(oval_dir) == "oval"


def test_empty_oval_still_detected_but_parse_fails(tmp_path: Path):
    oval_dir = tmp_path / "oval"
    oval_dir.mkdir()
    (oval_dir / "defs.xml").write_bytes(OVAL_ONLY_EMPTY)
    assert detect_package_format(oval_dir) == "oval"
    with pytest.raises(ValueError, match="no definition"):
        parse_oval_xml(OVAL_ONLY_EMPTY)


def test_parse_oval_maps_definitions():
    doc = parse_oval_xml(OVAL_WITH_DEFS)
    assert len(doc.definitions) == 2
    assert doc.definitions[0].definition_id == "oval:com.example:def:1"
    assert "foo" in doc.definitions[0].title
    assert doc.definitions[1].definition_class == "vulnerability"
    assert doc.version == "5.11"


def test_oval_package_is_valid_secaudit_package(tmp_path: Path):
    raw = tmp_path / "upload"
    raw.mkdir()
    (raw / "defs.xml").write_bytes(OVAL_WITH_DEFS)
    package_dir, source_format = prepare_upload_package(raw)
    assert source_format == "oval"

    validate_profile_package(package_dir)
    loaded = load_profile_package(package_dir)
    assert loaded["profile"]["source_format"] == "oval"

    rules = load_profile_rules_metadata(package_dir)
    assert len(rules) == 2
    assert rules[0]["scap_rule_id"] == "oval:com.example:def:1"

    assert (package_dir / "scap_oval.xml").is_file()
    assert resolve_oval_path(package_dir) == package_dir / "scap_oval.xml"
    scripts = discover_check_scripts(package_dir, loaded["profile"])
    script_text = (package_dir / scripts[0]["script_file"]).read_text(encoding="utf-8")
    assert "oscap oval eval" in script_text


def test_convert_oval_package_dir_directly(tmp_path: Path):
    raw = tmp_path / "upload"
    raw.mkdir()
    (raw / "defs.xml").write_bytes(OVAL_WITH_DEFS)
    out = convert_oval_package_dir(raw)
    assert (out / "scap_oval.xml").is_file()


def test_xccdf_preserves_referenced_oval_file(tmp_path: Path):
    raw = tmp_path / "upload"
    raw.mkdir()
    (raw / "benchmark.xml").write_bytes(XCCDF_WITH_OVAL_REF)
    (raw / "example-oval.xml").write_bytes(OVAL_WITH_DEFS)

    package_dir, source_format = prepare_upload_package(raw)
    assert source_format == "xccdf"
    assert (package_dir / "scap_benchmark.xml").is_file()
    assert (package_dir / "example-oval.xml").is_file()

    benchmark_path = package_dir / "scap_benchmark.xml"
    content_files = resolve_scap_content_files(package_dir, benchmark_path)
    names = {p.name for p in content_files}
    assert "scap_benchmark.xml" in names
    assert "example-oval.xml" in names


def test_datastream_detected_as_xccdf(tmp_path: Path):
    raw = tmp_path / "upload"
    raw.mkdir()
    (raw / "ds.xml").write_bytes(DATASTREAM)
    assert detect_package_format(raw) == "xccdf"

    benchmark = parse_xccdf_xml(DATASTREAM)
    assert benchmark.is_datastream is True
    assert len(benchmark.rules) == 1

    package_dir, source_format = prepare_upload_package(raw)
    assert source_format == "xccdf"
    loaded = load_profile_package(package_dir)
    assert loaded["profile"].get("scap_datastream") is True


def test_prepare_upload_package_converts_xccdf(tmp_path: Path):
    raw = tmp_path / "upload"
    raw.mkdir()
    (raw / "cis.xml").write_bytes(SAMPLE_XCCDF)
    package_dir, source_format = prepare_upload_package(raw)
    assert source_format == "xccdf"
    validate_profile_package(package_dir)


def test_xccdf_zip_roundtrip(tmp_path: Path):
    archive = tmp_path / "cis.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("nested/benchmark.xml", SAMPLE_XCCDF)

    extract = tmp_path / "extracted"
    extract.mkdir()
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(extract)

    package_dir, source_format = prepare_upload_package(extract)
    assert source_format == "xccdf"


def test_parse_xccdf_profiles_extracts_cis_levels():
    profiles = parse_xccdf_profiles(SAMPLE_XCCDF_WITH_PROFILES)
    assert len(profiles) == 2
    assert profiles[0].profile_id.endswith("Level_1")
    assert profiles[0].title == "CIS Level 1"


def test_materialize_xccdf_package_stores_profile_metadata(tmp_path: Path):
    benchmark = parse_xccdf_xml(SAMPLE_XCCDF_WITH_PROFILES)
    profile_id = "xccdf_org.cisecurity.benchmarks_profile_Level_1"
    package_dir = materialize_xccdf_package(
        benchmark,
        tmp_path / "pkg",
        xccdf_bytes=SAMPLE_XCCDF_WITH_PROFILES,
        scap_profile_id=profile_id,
        profile_title="CIS Level 1",
        profile_family="custom",
    )
    loaded = load_profile_package(package_dir)
    assert loaded["profile"]["scap_profile_id"] == profile_id
    assert loaded["profile"]["profile_family"] == "custom"
    assert resolve_scap_profile_id(package_dir) == profile_id
    rules = load_profile_rules_metadata(package_dir)
    assert len(rules) == 2
