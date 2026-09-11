from secaudit_core.enums import CheckStatus
from secaudit_core.playbook_compliance import parse_playbook_compliance_checks


def test_parse_checks_from_compliance_summary_json():
    summary = {
        "target": "host-1",
        "total": "3",
        "passed": "1",
        "failed": "2",
        "format": "STATUS|rule_id|summary|detail",
        "checks": [
            "FAIL|RULE0001|Ensure cramfs is disabled.|kernel module is available",
            "PASS|RULE0006|Ensure squashfs is disabled.|kernel module is not available",
            "FAIL|RULE0009|Ensure /tmp is separate.|not a mount point",
        ],
    }
    import json

    output = (
        "Playbook completed (connection: host-1=ssh)\n"
        f"OK [host-1] Ubuntu CRE compliance summary: {json.dumps(summary, ensure_ascii=False)}"
    )
    checks = parse_playbook_compliance_checks(output)
    assert len(checks) == 3
    assert checks[0]["tech_name"] == "RULE0001"
    assert checks[0]["status"] == CheckStatus.FAIL
    assert checks[1]["status"] == CheckStatus.PASS
    assert "cramfs" in checks[0]["message"]


def test_parse_checks_from_truncated_output():
    output = (
        'OK [h] summary: {"checks":["FAIL|RULE0001|Summary one.|detail one",'
        '"PASS|RULE0002|Summary two.|detail two","FAIL|RULE00'
    )
    checks = parse_playbook_compliance_checks(output)
    assert [c["tech_name"] for c in checks] == ["RULE0001", "RULE0002"]
