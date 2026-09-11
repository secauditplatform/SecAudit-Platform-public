from datetime import UTC, datetime
from types import SimpleNamespace

from secaudit_core.enums import CheckStatus, JobStatus
from secaudit_core.report_i18n import DEFAULT_REPORT_LOCALE, resolve_report_locale, status_labels_for_locale
from secaudit_core.reports import render_run_report_html


def _sample():
    check = SimpleNamespace(
        host_id=1,
        rule_tech_name="ssh.permit_root",
        status=CheckStatus.PASS,
        message="ok",
    )
    run = SimpleNamespace(
        id=42,
        status=JobStatus.COMPLETED,
        created_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        check_results=[check],
        job=SimpleNamespace(name="demo-job"),
    )
    profile = SimpleNamespace(profile_name="Demo Profile", package_path=None, rules=[])
    hosts = {1: SimpleNamespace(name="host-a")}
    return run, profile, hosts


def test_report_html_uses_english_when_locale_en():
    run, profile, hosts = _sample()
    html = render_run_report_html(run, profile, hosts, locale="en")
    assert 'lang="en"' in html
    assert "Compliance report" in html
    assert "Configuration check results" in html
    assert "Check details" in html
    assert "Отчёт" not in html
    assert "Соответствие" not in html


def test_report_html_uses_russian_when_locale_ru():
    run, profile, hosts = _sample()
    html = render_run_report_html(run, profile, hosts, locale="ru")
    assert 'lang="ru"' in html
    assert "Отчёт о соответствии" in html
    assert "Результаты проверки конфигурации" in html
    assert "Детализация проверок" in html
    assert "Compliance report" not in html


def test_pdf_status_labels_are_localized():
    labels = status_labels_for_locale("ru", for_pdf=True)
    assert labels["pass"] == "Пройдено"
    assert labels["fail"] == "Не пройдено"


def test_resolve_report_locale_prefers_query_param():
    assert resolve_report_locale("en", accept_language="ru") == "en"


def test_resolve_report_locale_defaults_to_english():
    assert resolve_report_locale(None) == DEFAULT_REPORT_LOCALE


def test_resolve_report_locale_uses_accept_language():
    assert resolve_report_locale(None, accept_language="en-US,en;q=0.9") == "en"


def test_report_html_defaults_to_english_without_locale():
    run, profile, hosts = _sample()
    html = render_run_report_html(run, profile, hosts)
    assert 'lang="en"' in html
    assert "Compliance report" in html
    assert "Отчёт" not in html


def test_report_html_includes_rule_description_from_profile_package(tmp_path, monkeypatch):
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "description.json").write_text(
        '{"version":1,"label":"Demo","profile_rules":"profile_rules.json"}',
        encoding="utf-8",
    )
    (package_dir / "profile_rules.json").write_text(
        """{
  "version": 1,
  "format": "secaudit.profile_rules",
  "rules": [{
    "tech_name": "ssh.permit_root",
    "requirement_id": "ssh.permit_root",
    "title": "Disable root SSH login",
    "explanation": "Root must not be allowed to log in over SSH.",
    "impact": "High",
    "scope": "sshd_config"
  }]
}""",
        encoding="utf-8",
    )

    check = SimpleNamespace(
        host_id=1,
        rule_tech_name="ssh.permit_root",
        status=CheckStatus.FAIL,
        message="PermitRootLogin yes",
    )
    run = SimpleNamespace(
        id=7,
        status=JobStatus.COMPLETED,
        created_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        check_results=[check],
        job=SimpleNamespace(name="demo-job"),
    )
    profile = SimpleNamespace(profile_name="Demo Profile", package_path=str(package_dir), rules=[])
    hosts = {1: SimpleNamespace(name="host-a")}

    html = render_run_report_html(run, profile, hosts, locale="en")
    assert "Disable root SSH login" in html
    assert "Root must not be allowed to log in over SSH." in html
    assert "PermitRootLogin yes" in html
    assert "ssh.permit_root" in html
    assert "check-card" in html
    assert "req-panel" in html
    assert "check-card__result" in html
