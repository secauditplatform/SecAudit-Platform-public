"""OpenSCAP XCCDF evaluation helpers (results parse, benchmark resolve)."""

from __future__ import annotations

import json
from pathlib import Path

from defusedxml import ElementTree as DefusedET

from secaudit_core.enums import CheckStatus

OSC_RESULT_TO_STATUS: dict[str, CheckStatus] = {
    "pass": CheckStatus.PASS,
    "fail": CheckStatus.FAIL,
    "error": CheckStatus.ERROR,
    "notchecked": CheckStatus.SKIP,
    "notapplicable": CheckStatus.SKIP,
    "notselected": CheckStatus.SKIP,
    "informational": CheckStatus.PASS,
    "fixed": CheckStatus.PASS,
}

# OVAL definition results (oscap oval eval) → SecAudit status.
OVAL_RESULT_TO_STATUS: dict[str, CheckStatus] = {
    "true": CheckStatus.PASS,
    "false": CheckStatus.FAIL,
    "error": CheckStatus.ERROR,
    "unknown": CheckStatus.SKIP,
    "not evaluated": CheckStatus.SKIP,
    "not applicable": CheckStatus.SKIP,
}


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _profile_meta(package_dir: Path) -> dict:
    from secaudit_core.profile_packages import DESCRIPTION_FILE, _find_profile_file

    profile_file = _find_profile_file(package_dir)
    if profile_file and profile_file.is_file():
        try:
            return json.loads(profile_file.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            pass
    description = package_dir / DESCRIPTION_FILE
    if description.is_file():
        try:
            return json.loads(description.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            pass
    return {}


def resolve_scap_benchmark_path(package_dir: Path) -> Path | None:
    """Return path to XCCDF benchmark (or SCAP data-stream) XML inside a package."""
    direct = package_dir / "scap_benchmark.xml"
    if direct.is_file():
        return direct

    ref = _profile_meta(package_dir).get("scap_xccdf_path")
    if ref:
        candidate = package_dir / str(ref)
        if candidate.is_file():
            return candidate
    return None


def resolve_scap_profile_id(package_dir: Path, *, db_profile_id: str | None = None) -> str | None:
    """Return XCCDF profile id for ``oscap xccdf eval --profile``."""
    if db_profile_id:
        return db_profile_id
    return _profile_meta(package_dir).get("scap_profile_id") or None


def resolve_oval_path(package_dir: Path) -> Path | None:
    """Return path to the primary OVAL definitions file for OVAL-only packages."""
    direct = package_dir / "scap_oval.xml"
    if direct.is_file():
        return direct

    ref = _profile_meta(package_dir).get("scap_oval_path")
    if ref:
        candidate = package_dir / str(ref)
        if candidate.is_file():
            return candidate
    return None


def resolve_scap_content_files(package_dir: Path, benchmark_path: Path) -> list[Path]:
    """Return all SCAP XML files that must be uploaded together for evaluation.

    Real XCCDF benchmarks reference external OVAL/CPE files via ``check-content-ref``;
    those siblings must be present next to the benchmark so ``oscap`` can resolve them.
    """
    files: list[Path] = [benchmark_path]
    seen = {benchmark_path.name}

    meta = _profile_meta(package_dir)
    for ref in meta.get("scap_extra_files") or []:
        candidate = package_dir / str(ref)
        if candidate.is_file() and candidate.name not in seen:
            files.append(candidate)
            seen.add(candidate.name)

    # Fallback: include any sibling *.xml that is not a generated artifact.
    for candidate in sorted(package_dir.glob("*.xml")):
        if candidate.name in seen:
            continue
        files.append(candidate)
        seen.add(candidate.name)
    return files


def map_oval_result_to_status(result: str) -> CheckStatus:
    normalized = (result or "").strip().lower()
    return OVAL_RESULT_TO_STATUS.get(normalized, CheckStatus.ERROR)


def parse_oval_results_xml(content: bytes) -> dict[str, str]:
    """Parse ``oscap oval eval`` results XML into {definition_id: result}."""
    try:
        root = DefusedET.fromstring(content)
    except DefusedET.ParseError as exc:
        raise ValueError(f"Invalid OVAL results XML: {exc}") from exc

    outcomes: dict[str, str] = {}
    for node in root.iter():
        if _local_name(node.tag) != "definition":
            continue
        def_id = (node.get("definition_id") or node.get("id") or "").strip()
        result = (node.get("result") or "").strip().lower()
        if def_id and result:
            outcomes[def_id] = result
    return outcomes


def map_oscap_result_to_status(result: str) -> CheckStatus:
    normalized = (result or "").strip().lower()
    return OSC_RESULT_TO_STATUS.get(normalized, CheckStatus.ERROR)


def parse_xccdf_results_xml(content: bytes) -> dict[str, str]:
    """Parse oscap XCCDF results XML into {rule_id: result}."""
    try:
        root = DefusedET.fromstring(content)
    except DefusedET.ParseError as exc:
        raise ValueError(f"Invalid XCCDF results XML: {exc}") from exc

    outcomes: dict[str, str] = {}
    for node in root.iter():
        if _local_name(node.tag) != "rule-result":
            continue
        rule_id = (node.get("idref") or "").strip()
        if not rule_id:
            continue
        result_text = ""
        for child in list(node):
            if _local_name(child.tag) == "result":
                result_text = (child.text or "").strip().lower()
                break
        if result_text:
            outcomes[rule_id] = result_text
    return outcomes


def merge_scap_and_script_results(
    *,
    db_rules: list[dict],
    scap_outcomes: dict[str, str],
    script_results: list[dict],
    result_kind: str = "xccdf",
) -> list[dict]:
    """Merge OpenSCAP rule outcomes with interpreter script output by tech_name.

    ``result_kind`` selects the outcome→status mapping: ``xccdf`` (rule-result strings)
    or ``oval`` (definition result strings such as true/false/unknown).
    """
    mapper = map_oval_result_to_status if result_kind == "oval" else map_oscap_result_to_status
    engine = "oval" if result_kind == "oval" else "oscap"
    script_by_tech = {item["tech_name"]: item for item in script_results}
    merged: list[dict] = []

    for rule in db_rules:
        tech_name = rule["tech_name"]
        scap_rule_id = rule.get("scap_rule_id")
        title = rule.get("title") or tech_name

        if scap_rule_id and scap_rule_id in scap_outcomes:
            osc_status = mapper(scap_outcomes[scap_rule_id])
            message = f"{title} ({engine}: {scap_outcomes[scap_rule_id]})"
            merged.append(
                {
                    "tech_name": tech_name,
                    "status": osc_status,
                    "message": message[:500],
                    "source": engine,
                }
            )
            continue

        script_item = script_by_tech.get(tech_name)
        if script_item:
            merged.append(
                {
                    "tech_name": tech_name,
                    "status": script_item["status"],
                    "message": script_item.get("message") or title,
                    "source": "script",
                }
            )
            continue

        if scap_rule_id:
            merged.append(
                {
                    "tech_name": tech_name,
                    "status": CheckStatus.SKIP,
                    "message": f"{title}: no {engine} result (rule {scap_rule_id})",
                    "source": engine,
                }
            )
        else:
            merged.append(
                {
                    "tech_name": tech_name,
                    "status": CheckStatus.SKIP,
                    "message": f"{title}: no SCAP rule id",
                    "source": "none",
                }
            )
    return merged
