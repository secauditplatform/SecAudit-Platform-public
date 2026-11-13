"""Parse check-script output into per-rule statuses.

Supports two contracts in parallel:

1. **JSONL** (preferred) — one JSON object per line::

       {"rule":"RULE1","status":"FAIL","actual":"...","expected":"...","message":"..."}

   Aliases: ``tech_name`` for ``rule``. Status is case-insensitive
   ``PASS`` / ``FAIL`` / ``SKIP`` / ``ERROR``.

2. **Legacy regex** — ``InterpreterRule.regex`` captures that contain a
   ``PASS|FAIL|SKIP|ERROR`` token (word-boundary; avoids banner ``error`` noise
   only when the token is absent).

Callers must invoke this on the **full** script stdout/stderr **before**
truncating for ``raw_output`` storage (``RAW_OUTPUT_MAX_CHARS``).
"""

from __future__ import annotations

import json
import re
from typing import Any

from secaudit_core.enums import CheckStatus

_STATUS_TOKEN = re.compile(r"\b(PASS|FAIL|SKIP|ERROR)\b", re.IGNORECASE)
_JSONL_STATUSES = frozenset({"pass", "fail", "skip", "error"})


def parse_jsonl_check_lines(output: str) -> list[dict[str, Any]]:
    """Stream JSONL check lines from output (ignores non-JSON lines)."""
    results: list[dict[str, Any]] = []
    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        rule = payload.get("rule") if payload.get("rule") is not None else payload.get("tech_name")
        status_raw = payload.get("status")
        if rule is None or status_raw is None:
            continue
        tech_name = str(rule).strip()
        status_key = str(status_raw).strip().lower()
        if not tech_name or status_key not in _JSONL_STATUSES:
            continue

        message_parts: list[str] = []
        message = payload.get("message")
        if message is not None and str(message).strip():
            message_parts.append(str(message).strip())
        has_actual = "actual" in payload
        has_expected = "expected" in payload
        if has_actual or has_expected:
            message_parts.append(
                f"actual={payload.get('actual')!s}; expected={payload.get('expected')!s}"
            )
        results.append(
            {
                "tech_name": tech_name,
                "status": CheckStatus(status_key),
                "message": " | ".join(message_parts) if message_parts else tech_name,
                "raw": line,
                "source": "jsonl",
            }
        )
    return results


def _apply_regex_rules(output: str, rules: list[dict]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for rule in rules:
        pattern_text = rule.get("regex")
        if not pattern_text:
            continue
        pattern = re.compile(str(pattern_text), re.MULTILINE)
        for match in pattern.finditer(output or ""):
            captured = match.group(1) if match.lastindex else match.group(0)
            status = CheckStatus.PENDING
            message = captured.strip()
            status_match = _STATUS_TOKEN.search(captured)
            if status_match:
                status = CheckStatus(status_match.group(1).lower())
                detail = re.sub(
                    r".*?\b(?:PASS|FAIL|SKIP|ERROR)\b\s*:?\s*",
                    "",
                    captured,
                    count=1,
                    flags=re.IGNORECASE,
                ).strip()
                if detail:
                    message = detail
            tech_name = rule.get("tech_name") or rule.get("techName")
            if not tech_name:
                continue
            results.append(
                {
                    "tech_name": str(tech_name),
                    "status": status,
                    "message": message,
                    "raw": captured,
                    "source": "regex",
                }
            )
    return results


def apply_interpreter_rules(
    output: str,
    rules: list[dict],
) -> list[dict]:
    """Apply JSONL (preferred) then legacy regex rules to script output.

    JSONL hits for a ``tech_name`` win over regex for the same name. Regex still
    covers rules with no JSONL line. When ``rules`` is empty, all JSONL lines
    are returned.
    """
    allowed = {
        str(rule.get("tech_name") or rule.get("techName") or "").strip()
        for rule in rules
        if (rule.get("tech_name") or rule.get("techName"))
    }
    allowed.discard("")

    by_tech: dict[str, dict[str, Any]] = {}
    ordered: list[dict[str, Any]] = []

    for item in parse_jsonl_check_lines(output):
        tech = item["tech_name"]
        if allowed and tech not in allowed:
            # Still accept JSONL for known aliases when rules list is scoped —
            # keep if no allow-list, else only listed tech names.
            continue
        if tech in by_tech:
            idx = next(i for i, row in enumerate(ordered) if row["tech_name"] == tech)
            ordered[idx] = item
            by_tech[tech] = item
        else:
            by_tech[tech] = item
            ordered.append(item)

    for item in _apply_regex_rules(output, rules):
        tech = item["tech_name"]
        if tech in by_tech:
            continue
        by_tech[tech] = item
        ordered.append(item)

    return ordered
