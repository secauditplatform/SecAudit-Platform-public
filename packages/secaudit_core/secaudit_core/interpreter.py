import re

from secaudit_core.enums import CheckStatus


def apply_interpreter_rules(
    output: str,
    rules: list[dict],
) -> list[dict]:
    """Apply interpreter-style regex rules to script output."""
    results: list[dict] = []
    for rule in rules:
        pattern = re.compile(rule["regex"], re.MULTILINE)
        for match in pattern.finditer(output):
            captured = match.group(1) if match.lastindex else match.group(0)
            status = CheckStatus.PENDING
            message = captured.strip()
            status_match = re.search(r"\b(PASS|FAIL|SKIP|ERROR)\b", captured, re.IGNORECASE)
            if status_match:
                status = CheckStatus(status_match.group(1).lower())
                detail = re.sub(r".*?\b(?:PASS|FAIL|SKIP|ERROR)\b\s*:?\s*", "", captured, count=1).strip()
                if detail:
                    message = detail
            tech_name = rule.get("tech_name") or rule.get("techName")
            if not tech_name:
                continue
            results.append(
                {
                    "tech_name": tech_name,
                    "status": status,
                    "message": message,
                    "raw": captured,
                }
            )
    return results
