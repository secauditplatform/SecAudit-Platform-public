"""Tests for OpenSCAP results parsing and merge logic."""

from pathlib import Path

from secaudit_core.enums import CheckStatus
from secaudit_core.oscap import (
    map_oval_result_to_status,
    merge_scap_and_script_results,
    parse_oval_results_xml,
    parse_xccdf_results_xml,
    resolve_scap_benchmark_path,
)

SAMPLE_RESULTS = b"""<?xml version="1.0" encoding="UTF-8"?>
<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test" version="1.2">
  <rule-result idref="xccdf_org.cisecurity.benchmarks_rule_1.1.1.1" role="full">
    <result>pass</result>
  </rule-result>
  <rule-result idref="xccdf_org.cisecurity.benchmarks_rule_1.1.1.2" role="full">
    <result>fail</result>
  </rule-result>
  <rule-result idref="xccdf_org.cisecurity.benchmarks_rule_1.1.1.3" role="full">
    <result>notchecked</result>
  </rule-result>
</TestResult>
"""


def test_parse_xccdf_results_xml_maps_rule_outcomes():
    outcomes = parse_xccdf_results_xml(SAMPLE_RESULTS)
    assert outcomes["xccdf_org.cisecurity.benchmarks_rule_1.1.1.1"] == "pass"
    assert outcomes["xccdf_org.cisecurity.benchmarks_rule_1.1.1.2"] == "fail"
    assert outcomes["xccdf_org.cisecurity.benchmarks_rule_1.1.1.3"] == "notchecked"


def test_resolve_scap_benchmark_path_prefers_scap_benchmark_xml(tmp_path: Path):
    package = tmp_path / "pkg"
    package.mkdir()
    benchmark = package / "scap_benchmark.xml"
    benchmark.write_text("<Benchmark/>", encoding="utf-8")
    assert resolve_scap_benchmark_path(package) == benchmark


def test_merge_scap_and_script_results_prefers_oscap_then_script():
    db_rules = [
        {"tech_name": "RULE0001", "scap_rule_id": "xccdf_org.cisecurity.benchmarks_rule_1.1.1.1", "title": "Rule 1"},
        {"tech_name": "RULE0002", "scap_rule_id": "xccdf_org.cisecurity.benchmarks_rule_1.1.1.2", "title": "Rule 2"},
        {"tech_name": "RULE0003", "scap_rule_id": "xccdf_org.cisecurity.benchmarks_rule_1.1.1.3", "title": "Rule 3"},
    ]
    scap_outcomes = {
        "xccdf_org.cisecurity.benchmarks_rule_1.1.1.1": "pass",
        "xccdf_org.cisecurity.benchmarks_rule_1.1.1.2": "fail",
        "xccdf_org.cisecurity.benchmarks_rule_1.1.1.3": "notchecked",
    }
    script_results = [
        {"tech_name": "RULE0003", "status": CheckStatus.PASS, "message": "SCE shell pass"},
    ]

    merged = merge_scap_and_script_results(
        db_rules=db_rules,
        scap_outcomes=scap_outcomes,
        script_results=script_results,
    )
    by_tech = {item["tech_name"]: item for item in merged}

    assert by_tech["RULE0001"]["status"] == CheckStatus.PASS
    assert by_tech["RULE0001"]["source"] == "oscap"
    assert by_tech["RULE0002"]["status"] == CheckStatus.FAIL
    assert by_tech["RULE0003"]["status"] == CheckStatus.SKIP
    assert "notchecked" in by_tech["RULE0003"]["message"]
    assert by_tech["RULE0003"]["source"] == "oscap"


OVAL_RESULTS = b"""<?xml version="1.0" encoding="UTF-8"?>
<oval_results xmlns="http://oval.mitre.org/XMLSchema/oval-results-5">
  <results>
    <system>
      <definitions>
        <definition definition_id="oval:com.example:def:1" result="true"/>
        <definition definition_id="oval:com.example:def:2" result="false"/>
        <definition definition_id="oval:com.example:def:3" result="unknown"/>
      </definitions>
    </system>
  </results>
</oval_results>
"""


def test_parse_oval_results_xml_maps_definition_outcomes():
    outcomes = parse_oval_results_xml(OVAL_RESULTS)
    assert outcomes["oval:com.example:def:1"] == "true"
    assert outcomes["oval:com.example:def:2"] == "false"
    assert outcomes["oval:com.example:def:3"] == "unknown"


def test_map_oval_result_to_status():
    assert map_oval_result_to_status("true") == CheckStatus.PASS
    assert map_oval_result_to_status("false") == CheckStatus.FAIL
    assert map_oval_result_to_status("unknown") == CheckStatus.SKIP
    assert map_oval_result_to_status("not applicable") == CheckStatus.SKIP
    assert map_oval_result_to_status("bogus") == CheckStatus.ERROR


def test_merge_with_oval_result_kind():
    db_rules = [
        {"tech_name": "RULE0001", "scap_rule_id": "oval:com.example:def:1", "title": "Def 1"},
        {"tech_name": "RULE0002", "scap_rule_id": "oval:com.example:def:2", "title": "Def 2"},
    ]
    scap_outcomes = {
        "oval:com.example:def:1": "true",
        "oval:com.example:def:2": "false",
    }
    merged = merge_scap_and_script_results(
        db_rules=db_rules,
        scap_outcomes=scap_outcomes,
        script_results=[],
        result_kind="oval",
    )
    by_tech = {item["tech_name"]: item for item in merged}
    assert by_tech["RULE0001"]["status"] == CheckStatus.PASS
    assert by_tech["RULE0001"]["source"] == "oval"
    assert by_tech["RULE0002"]["status"] == CheckStatus.FAIL
    assert "oval: false" in by_tech["RULE0002"]["message"]


def test_merge_scap_and_script_results_uses_script_when_oscap_missing():
    db_rules = [
        {"tech_name": "RULE0004", "scap_rule_id": "xccdf_missing_rule", "title": "SCE rule"},
    ]
    merged = merge_scap_and_script_results(
        db_rules=db_rules,
        scap_outcomes={},
        script_results=[
            {"tech_name": "RULE0004", "status": CheckStatus.PASS, "message": "SCE shell pass"},
        ],
    )
    assert merged[0]["status"] == CheckStatus.PASS
    assert merged[0]["source"] == "script"
