"""Parse CRE compliance check lines from Ansible playbook output."""

from __future__ import annotations

import json
import re
from typing import Any

from secaudit_core.enums import CheckStatus

# STATUS|rule_id|summary|detail — emitted by *_compliance.yml debug summaries.
_CHECK_LINE_RE = re.compile(
    r"(?P<status>PASS|FAIL|SKIP|ERROR|NA|N/?A)"
    r"\|(?P<rule>[^|\"]+)"
    r"\|(?P<summary>[^|]*)"
    r"\|(?P<detail>[^|\"]*?)"
    r"(?=(?:\"|,|\s*\]|$))",
    re.IGNORECASE,
)

_STATUS_MAP = {
    "pass": CheckStatus.PASS,
    "fail": CheckStatus.FAIL,
    "skip": CheckStatus.SKIP,
    "error": CheckStatus.ERROR,
    "na": CheckStatus.SKIP,
    "n/a": CheckStatus.SKIP,
}


def _normalize_status(raw: str) -> CheckStatus:
    key = raw.strip().upper().replace("/", "")
    if key == "NA":
        return CheckStatus.SKIP
    return _STATUS_MAP.get(raw.strip().lower(), CheckStatus.ERROR)


def _message(summary: str, detail: str) -> str:
    summary = summary.strip()
    detail = detail.strip()
    if summary and detail:
        return f"{summary}: {detail}"
    return summary or detail


def _append_check(
    bucket: dict[str, dict[str, Any]],
    *,
    status: CheckStatus,
    rule: str,
    summary: str,
    detail: str,
) -> None:
    rule_id = rule.strip()
    if not rule_id:
        return
    bucket[rule_id] = {
        "tech_name": rule_id,
        "status": status,
        "message": _message(summary, detail),
        "summary": summary.strip(),
        "detail": detail.strip(),
    }


def _ingest_check_strings(bucket: dict[str, dict[str, Any]], values: list[Any]) -> None:
    for value in values:
        if not isinstance(value, str):
            continue
        match = _CHECK_LINE_RE.search(value.strip())
        if not match:
            continue
        _append_check(
            bucket,
            status=_normalize_status(match.group("status")),
            rule=match.group("rule"),
            summary=match.group("summary"),
            detail=match.group("detail"),
        )


def _try_parse_json_blob(text: str) -> Any | None:
    start = text.find("{")
    if start < 0:
        start = text.find("[")
    if start < 0:
        return None
    chunk = text[start:]
    decoder = json.JSONDecoder()
    try:
        value, _ = decoder.raw_decode(chunk)
        return value
    except json.JSONDecodeError:
        return None


def _walk_for_checks(bucket: dict[str, dict[str, Any]], node: Any) -> None:
    if isinstance(node, dict):
        checks = node.get("checks")
        if isinstance(checks, list):
            _ingest_check_strings(bucket, checks)
        elif isinstance(checks, str):
            _ingest_check_strings(bucket, [checks])
            nested = _try_parse_json_blob(checks)
            if nested is not None:
                _walk_for_checks(bucket, nested)
        for value in node.values():
            if value is checks:
                continue
            _walk_for_checks(bucket, value)
        return
    if isinstance(node, list):
        if node and all(isinstance(item, str) for item in node):
            _ingest_check_strings(bucket, node)
            return
        for item in node:
            _walk_for_checks(bucket, item)


def parse_playbook_compliance_checks(output: str | None) -> list[dict[str, Any]]:
    """Extract unique rule results from Ansible playbook stdout / event dump.

    Prefer structured ``checks`` arrays from CRE compliance summary debug tasks,
    then fall back to scanning for ``STATUS|rule_id|summary|detail`` lines.
    """
    text = (output or "").strip()
    if not text:
        return []

    bucket: dict[str, dict[str, Any]] = {}

    for line in text.splitlines():
        payload = _try_parse_json_blob(line)
        if payload is not None:
            _walk_for_checks(bucket, payload)

    # Also scan raw text so truncated JSON dumps still yield complete check rows.
    _ingest_check_strings(bucket, text.splitlines())
    for match in _CHECK_LINE_RE.finditer(text):
        _append_check(
            bucket,
            status=_normalize_status(match.group("status")),
            rule=match.group("rule"),
            summary=match.group("summary"),
            detail=match.group("detail"),
        )

    return sorted(bucket.values(), key=lambda item: item["tech_name"])
