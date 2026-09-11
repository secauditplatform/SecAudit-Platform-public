from datetime import UTC, datetime
from types import SimpleNamespace

from secaudit_core.enums import CheckStatus, JobStatus
from secaudit_core.reports import render_run_report_html


def test_report_autoescapes_persisted_job_host_and_result_fields():
    payload = '<img src=x onerror="alert(1)">'
    check = SimpleNamespace(
        host_id=1,
        rule_tech_name=f"rule-{payload}",
        status=CheckStatus.FAIL,
        message=f"message-{payload}",
    )
    run = SimpleNamespace(
        id=9,
        status=JobStatus.COMPLETED,
        created_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        check_results=[check],
        job=SimpleNamespace(name=f"job-{payload}"),
    )
    profile = SimpleNamespace(profile_name=f"profile-{payload}")
    hosts = {1: SimpleNamespace(name=f"host-{payload}")}

    html = render_run_report_html(run, profile, hosts)

    assert payload not in html
    assert "&lt;img src=x onerror=&#34;alert(1)&#34;&gt;" in html
    assert html.count("&lt;img") >= 5
