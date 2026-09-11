"""SCAP / XCCDF import: XXE-safe parse and synthetic SecAudit package materialization.

Supports XCCDF benchmarks, SCAP source data-streams, and standalone OVAL definitions.
Referenced OVAL/CPE files are preserved alongside the benchmark so that the worker
OpenSCAP executor can resolve them during ``oscap xccdf eval`` / ``oscap oval eval``.
"""

from __future__ import annotations

import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as DefusedET

from app.services.interpreter import _find_profile_file
from app.services.scap_remediation import (
    XccdfFix,
    classify_fix_system,
    plan_rule_remediation,
    render_remediation_ansible,
    render_remediation_shell,
)

DESCRIPTION_FILE = "description.json"
PROFILE_RULES_JSON = "profile_rules.json"

OVAL_MARKERS = (
    b"oval-definitions",
    b"oval_definitions",
    b"http://oval.mitre.org/XMLSchema/oval",
)

DATASTREAM_MARKERS = (
    b"data-stream-collection",
    b"scap.org/schema/scap/source",
)

SCE_CHECK_SYSTEMS = (
    "http://open-scap.org/page/SCE",
    "http://www.open-scap.org/page/SCE",
)

SEVERITY_MAP = {
    "unknown": "INFO",
    "info": "INFO",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
}


@dataclass
class XccdfRule:
    rule_id: str
    title: str
    description: str
    severity: str
    check_shell: str | None = None
    fix_shell: str | None = None
    fixes: list[XccdfFix] = field(default_factory=list)


@dataclass
class XccdfProfile:
    profile_id: str
    title: str
    description: str = ""


@dataclass
class XccdfBenchmark:
    benchmark_id: str
    title: str
    version: str
    description: str
    platform: str | None = None
    rules: list[XccdfRule] = field(default_factory=list)
    is_datastream: bool = False
    check_refs: list[str] = field(default_factory=list)


@dataclass
class OvalDefinition:
    definition_id: str
    title: str
    description: str
    definition_class: str


@dataclass
class OvalDocument:
    oval_id: str
    title: str
    version: str
    definitions: list[OvalDefinition] = field(default_factory=list)


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _child_text(element: Element, names: tuple[str, ...]) -> str:
    for child in element:
        if _local_name(child.tag) in names:
            text = "".join(child.itertext()).strip()
            if text:
                return text
    return ""


def _walk(element: Element):
    yield element
    for child in list(element):
        yield from _walk(child)


def _extract_fixes(rule_el: Element) -> list[XccdfFix]:
    """Collect all XCCDF <fix> payloads (shell, ansible, puppet, …)."""
    fixes: list[XccdfFix] = []
    for node in _walk(rule_el):
        if _local_name(node.tag) != "fix":
            continue
        system = (node.get("system") or "").strip()
        text = ""
        for child in list(node):
            if _local_name(child.tag) in ("fixtext", "fix-text"):
                text = "".join(child.itertext()).strip()
                if text:
                    break
        if not text:
            text = "".join(node.itertext()).strip()
        if text:
            fixes.append(XccdfFix(system=system, text=text))
    return fixes


def _extract_shell_from_fix(rule_el: Element) -> str | None:
    from app.services.scap_remediation import classify_fix_system

    for fix in _extract_fixes(rule_el):
        if classify_fix_system(fix.system) == "shell":
            return fix.text
    return None


def _extract_shell_from_check(rule_el: Element) -> str | None:
    for node in _walk(rule_el):
        if _local_name(node.tag) != "check":
            continue
        system = (node.get("system") or "").strip()
        if system not in SCE_CHECK_SYSTEMS and "sce" not in system.lower():
            # Inline script content without SCE is uncommon; still accept check-content shells.
            pass
        for child in list(node):
            local = _local_name(child.tag)
            if local in ("check-content", "check_content"):
                text = "".join(child.itertext()).strip()
                if text and ("\n" in text or text.startswith("#!") or "echo " in text):
                    return text
    return None


def _looks_like_datastream_bytes(content: bytes) -> bool:
    head = content[:16384].lower()
    return any(marker in head for marker in DATASTREAM_MARKERS)


def _looks_like_oval_bytes(content: bytes) -> bool:
    head = content[:8192].lower()
    if b"<benchmark" in head or b":benchmark" in head:
        return False
    if _looks_like_datastream_bytes(content):
        return False
    return any(marker in head for marker in OVAL_MARKERS)


def _looks_like_xccdf_bytes(content: bytes) -> bool:
    if _looks_like_datastream_bytes(content):
        return True
    head = content[:16384].lower()
    return b"<benchmark" in head or b":benchmark" in head or b"xccdf" in head


def _extract_check_content_refs(root: Element) -> list[str]:
    """Collect external file names referenced by XCCDF checks (OVAL/CPE/SCE hrefs)."""
    refs: list[str] = []
    seen: set[str] = set()
    for node in _walk(root):
        if _local_name(node.tag) not in ("check-content-ref", "check_content_ref"):
            continue
        href = (node.get("href") or "").strip()
        if not href or href.startswith(("http://", "https://", "#")):
            continue
        name = href.rsplit("/", 1)[-1]
        if name and name not in seen:
            refs.append(name)
            seen.add(name)
    return refs


def parse_xccdf_profiles(content: bytes) -> list[XccdfProfile]:
    """Extract XCCDF Profile elements (levels, tailored profiles)."""
    try:
        doc_root = DefusedET.fromstring(content)
    except DefusedET.ParseError as exc:
        raise ValueError(f"Invalid XCCDF XML: {exc}") from exc

    profiles: list[XccdfProfile] = []
    seen: set[str] = set()
    for node in _walk(doc_root):
        if _local_name(node.tag) != "Profile":
            continue
        profile_id = (node.get("id") or "").strip()
        if not profile_id or profile_id in seen:
            continue
        seen.add(profile_id)
        title = _child_text(node, ("title", "Title")) or profile_id
        description = _child_text(node, ("description", "Description", "rationale"))
        profiles.append(
            XccdfProfile(profile_id=profile_id, title=title, description=description)
        )
    return profiles


def infer_scap_profile_family(
    benchmark: XccdfBenchmark,
    profile: XccdfProfile | None = None,
) -> str:
    """All SCAP uploads are tagged as custom (no trademark family inference)."""
    _ = (benchmark, profile)
    return "custom"


def parse_xccdf_xml(content: bytes) -> XccdfBenchmark:
    """Parse XCCDF Benchmark XML with defusedxml (XXE-safe). Fail loud on invalid XML."""
    try:
        doc_root = DefusedET.fromstring(content)
    except DefusedET.ParseError as exc:
        raise ValueError(f"Invalid XCCDF XML: {exc}") from exc

    is_datastream = _local_name(doc_root.tag) in ("data-stream-collection", "data_stream_collection")
    root = doc_root
    if _local_name(root.tag) != "Benchmark":
        # SCAP data-streams and some bundles wrap Benchmark; search the tree.
        benchmark_el = None
        for node in _walk(doc_root):
            if _local_name(node.tag) == "Benchmark":
                benchmark_el = node
                break
        if benchmark_el is None:
            raise ValueError("XCCDF document must contain a Benchmark element")
        root = benchmark_el

    benchmark_id = (root.get("id") or "xccdf-benchmark").strip()
    title = _child_text(root, ("title", "Title")) or benchmark_id
    version = (
        _child_text(root, ("version", "Version"))
        or root.get("style")
        or "1.0.0"
    )
    description = _child_text(root, ("description", "Description", "notice"))
    platform = None
    for child in list(root):
        if _local_name(child.tag) == "platform":
            platform = (child.get("idref") or "".join(child.itertext()).strip() or None)
            break

    rules: list[XccdfRule] = []
    seen_ids: set[str] = set()
    for node in _walk(root):
        if _local_name(node.tag) != "Rule":
            continue
        # Skip nested Group-only wrappers without id
        rule_id = (node.get("id") or "").strip()
        if not rule_id or rule_id in seen_ids:
            continue
        # Prefer selected/selectedable rules; still import unselected for catalog
        seen_ids.add(rule_id)
        severity_raw = (node.get("severity") or "unknown").strip().lower()
        severity = SEVERITY_MAP.get(severity_raw, severity_raw.upper() or "INFO")
        rule_title = _child_text(node, ("title", "Title")) or rule_id
        rule_desc = _child_text(node, ("description", "Description", "rationale"))
        fixes = _extract_fixes(node)
        fix_shell = next(
            (fix.text for fix in fixes if classify_fix_system(fix.system) == "shell"),
            None,
        )
        rules.append(
            XccdfRule(
                rule_id=rule_id,
                title=rule_title,
                description=rule_desc,
                severity=severity,
                check_shell=_extract_shell_from_check(node),
                fix_shell=fix_shell,
                fixes=fixes,
            )
        )

    if not rules:
        raise ValueError("XCCDF Benchmark contains no Rule elements")

    return XccdfBenchmark(
        benchmark_id=benchmark_id,
        title=title,
        version=str(version)[:32],
        description=description,
        platform=platform,
        rules=rules,
        is_datastream=is_datastream,
        check_refs=_extract_check_content_refs(doc_root),
    )


def parse_oval_xml(content: bytes) -> OvalDocument:
    """Parse an OVAL definitions document (XXE-safe) into a catalog of definitions."""
    try:
        root = DefusedET.fromstring(content)
    except DefusedET.ParseError as exc:
        raise ValueError(f"Invalid OVAL XML: {exc}") from exc

    if _local_name(root.tag) not in ("oval_definitions", "oval-definitions"):
        found = None
        for node in _walk(root):
            if _local_name(node.tag) in ("oval_definitions", "oval-definitions"):
                found = node
                break
        if found is None:
            raise ValueError("OVAL document must contain an oval_definitions element")
        root = found

    version = "5.11"
    for node in _walk(root):
        if _local_name(node.tag) == "schema_version":
            version = ("".join(node.itertext()).strip() or version)[:32]
            break

    definitions: list[OvalDefinition] = []
    seen: set[str] = set()
    for node in _walk(root):
        if _local_name(node.tag) != "definition":
            continue
        def_id = (node.get("id") or "").strip()
        if not def_id or def_id in seen:
            continue
        seen.add(def_id)
        def_class = (node.get("class") or "compliance").strip()
        title = ""
        description = ""
        for meta_node in _walk(node):
            local = _local_name(meta_node.tag)
            if local == "title" and not title:
                title = "".join(meta_node.itertext()).strip()
            elif local == "description" and not description:
                description = "".join(meta_node.itertext()).strip()
        definitions.append(
            OvalDefinition(
                definition_id=def_id,
                title=title or def_id,
                description=description,
                definition_class=def_class,
            )
        )

    if not definitions:
        raise ValueError("OVAL document contains no definition elements")

    oval_id = definitions[0].definition_id.rsplit(":def:", 1)[0] or "oval-definitions"
    return OvalDocument(
        oval_id=oval_id,
        title=f"OVAL Definitions ({len(definitions)})",
        version=version,
        definitions=definitions,
    )


def _safe_slug(value: str, *, max_len: int = 80) -> str:
    cleaned = re.sub(r"[^\w.\-]+", "_", value.strip(), flags=re.UNICODE)
    cleaned = re.sub(r"_+", "_", cleaned).strip("._-")
    if not cleaned:
        cleaned = "xccdf_benchmark"
    return cleaned[:max_len]


def _req_mnemonic(index: int) -> str:
    return f"REQ{index}"


def _req_context(index: int) -> str:
    return f"REQ{index:04d}"


def _csv_escape_field(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n").replace(";", ",")


def _write_profile_rules_json(dest: Path, rules: list[dict]) -> None:
    (dest / PROFILE_RULES_JSON).write_text(
        json.dumps(
            {"version": 1, "format": "secaudit.profile_rules", "rules": rules},
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def _infer_os_meta(benchmark: XccdfBenchmark) -> dict:
    haystack = f"{benchmark.title} {benchmark.benchmark_id} {benchmark.platform or ''}".lower()
    if "windows" in haystack:
        return {
            "name": "Windows",
            "vendor": "Microsoft",
            "version": "",
            "icon": "ic_windows.svg",
        }
    return {
        "name": "Linux",
        "vendor": "SCAP",
        "version": "",
        "icon": "ic_linux.svg",
    }


def _category_slug_for_benchmark(benchmark: XccdfBenchmark) -> str:
    haystack = f"{benchmark.title} {benchmark.benchmark_id} {benchmark.platform or ''}".lower()
    if "windows" in haystack:
        return "windows-platform"
    if any(token in haystack for token in ("network", "cisco", "juniper", "firewall")):
        return "network-platform"
    return "linux-platform"


def _oscap_rule_check_lines(mnemonic: str, rule_id: str, title: str) -> list[str]:
    safe_title = title.replace('"', "'")
    return [
        f"# OpenSCAP eval when oscap + scap_benchmark.xml are available on target",
        f'_OSCAP_RULE="{rule_id}"',
        'if command -v oscap >/dev/null 2>&1 && [ -f "scap_benchmark.xml" ]; then',
        '  _OSCAP_RES=$(mktemp)',
        '  if oscap xccdf eval --rule "$_OSCAP_RULE" --results "$_OSCAP_RES" scap_benchmark.xml >/dev/null 2>&1; then',
        f'    if grep -q \'result="pass"\' "$_OSCAP_RES" 2>/dev/null; then',
        f'      echo "{mnemonic}= PASS: {safe_title} (oscap)"',
        "    else",
        f'      echo "{mnemonic}= FAIL: {safe_title} (oscap)"',
        "    fi",
        "  else",
        f'    echo "{mnemonic}= SKIP: oscap eval failed for rule {rule_id}"',
        "  fi",
        '  rm -f "$_OSCAP_RES"',
        "else",
        f'  echo "{mnemonic}= SKIP: No executable check in XCCDF '
        f'(rule {rule_id}; install oscap on target or embed SCE/shell check)"',
        "fi",
    ]


def materialize_xccdf_package(
    benchmark: XccdfBenchmark,
    dest: Path,
    *,
    xccdf_bytes: bytes | None = None,
    extra_files: list[tuple[str, bytes]] | None = None,
    scap_profile_id: str | None = None,
    profile_title: str | None = None,
    profile_family: str | None = None,
) -> Path:
    """Write a SecAudit package at dest root (scripts at package root for discover_check_scripts).

    ``extra_files`` are external SCAP content files (OVAL/CPE) referenced by the benchmark;
    they are written next to ``scap_benchmark.xml`` so ``oscap`` can resolve check-content refs.
    """
    dest.mkdir(parents=True, exist_ok=True)
    tech_name = _safe_slug(benchmark.benchmark_id or benchmark.title, max_len=120)
    if scap_profile_id:
        profile_slug = _safe_slug(scap_profile_id.rsplit(":", 1)[-1], max_len=48)
        tech_name = f"{tech_name}_{profile_slug}"[:120]
    script_stem = _safe_slug(tech_name, max_len=60) + "_scripts"

    os_meta = _infer_os_meta(benchmark)
    software_meta = {
        "name": benchmark.title[:200],
        "vendor": "SCAP",
        "category": "SCAP / XCCDF",
        "version": benchmark.version,
    }

    resolved_family = profile_family or infer_scap_profile_family(benchmark)
    benchmark_ref = benchmark.benchmark_id
    profile_meta = {
        "profile_name": tech_name,
        "is_active": True,
        "version": benchmark.version or "1.0",
        "overview": (benchmark.description or f"Imported from XCCDF Benchmark {benchmark.benchmark_id}")[
            :2000
        ],
        "os": os_meta,
        "software": software_meta,
        "encoding": "utf-8",
        "profile_rules": PROFILE_RULES_JSON,
        "source_format": "xccdf",
        "scap_benchmark_id": benchmark.benchmark_id,
        "category_slug": _category_slug_for_benchmark(benchmark),
        "profile_family": resolved_family,
        "benchmark_ref": benchmark_ref,
    }
    if scap_profile_id:
        profile_meta["scap_profile_id"] = scap_profile_id
        if profile_title:
            profile_meta["profile_title"] = profile_title
    if xccdf_bytes:
        (dest / "scap_benchmark.xml").write_bytes(xccdf_bytes)
        profile_meta["scap_xccdf_path"] = "scap_benchmark.xml"
    if benchmark.is_datastream:
        profile_meta["scap_datastream"] = True

    written_extra: list[str] = []
    for name, data in extra_files or []:
        safe_name = Path(name).name
        if not safe_name or safe_name == "scap_benchmark.xml":
            continue
        (dest / safe_name).write_bytes(data)
        if safe_name not in written_extra:
            written_extra.append(safe_name)
    if written_extra:
        profile_meta["scap_extra_files"] = written_extra
    (dest / DESCRIPTION_FILE).write_text(
        json.dumps(profile_meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    rules_records: list[dict] = []
    audit_lines = [
        "#!/bin/bash",
        f"# Auto-generated from XCCDF Benchmark: {benchmark.benchmark_id}",
        "# Rules without embedded shell are evaluated via the worker OpenSCAP executor "
        "(full oscap xccdf eval); per-rule oscap below is a fallback when jobs use SSH scripts only.",
        "export LC_ALL=C",
        'cd "$(dirname "$0")" 2>/dev/null || true',
        "",
    ]
    rem_plans = []
    for index, rule in enumerate(benchmark.rules, start=1):
        mnemonic = _req_mnemonic(index)
        context = _req_context(index)
        title = _csv_escape_field(rule.title)[:500]
        description = _csv_escape_field(rule.description)[:4000]
        risk = rule.severity
        rules_records.append(
            {
                "num": str(index),
                "title": title,
                "explanation": description,
                "impact": risk,
                "criticality": rule.severity,
                "check_script": script_stem,
                "requirement_id": context,
                "match_pattern": f"{mnemonic}=(.*)",
                "scap_rule_id": rule.rule_id,
            }
        )

        safe_title = title.replace('"', "'")
        if rule.check_shell:
            audit_lines.append(f"# --- {rule.rule_id}: {rule.title} ---")
            # Run embedded check in a subshell; treat exit 0 as PASS.
            audit_lines.append("(")
            for line in rule.check_shell.splitlines():
                audit_lines.append(f"  {line}")
            audit_lines.append(")")
            audit_lines.append("if [ $? -eq 0 ]; then")
            audit_lines.append(f'  echo "{mnemonic}= PASS: {safe_title}"')
            audit_lines.append("else")
            audit_lines.append(f'  echo "{mnemonic}= FAIL: {safe_title}"')
            audit_lines.append("fi")
            audit_lines.append("")
        else:
            audit_lines.extend(_oscap_rule_check_lines(mnemonic, rule.rule_id, safe_title))
            audit_lines.append("")

        rem_plans.append(
            plan_rule_remediation(
                rule_id=rule.rule_id,
                title=rule.title,
                description=rule.description,
                mnemonic=mnemonic,
                fixes=list(rule.fixes)
                or (
                    [XccdfFix(system="urn:xccdf:fix:script:sh", text=rule.fix_shell)]
                    if rule.fix_shell
                    else []
                ),
            )
        )

    _write_profile_rules_json(dest, rules_records)
    script_path = dest / f"{script_stem}.sh"
    script_path.write_text("\n".join(audit_lines) + "\n", encoding="utf-8")
    script_path.chmod(script_path.stat().st_mode | 0o111)

    # Always materialize remediations (fixtext, templates, or explicit UNSUPPORTED).
    rem_path = dest / f"{script_stem}_remediation.sh"
    rem_path.write_text(render_remediation_shell(benchmark.benchmark_id, rem_plans), encoding="utf-8")
    rem_path.chmod(rem_path.stat().st_mode | 0o111)

    ansible_path = dest / f"{script_stem}_ansible_remediation.yml"
    ansible_path.write_text(
        render_remediation_ansible(benchmark.benchmark_id, rem_plans), encoding="utf-8"
    )

    return dest


def find_xccdf_files(package_dir: Path) -> list[Path]:
    matches: list[Path] = []
    for path in sorted(package_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".xml", ".xccdf"}:
            continue
        try:
            content = path.read_bytes()
        except OSError:
            continue
        if _looks_like_xccdf_bytes(content):
            matches.append(path)
    return matches


def find_oval_only_files(package_dir: Path) -> list[Path]:
    matches: list[Path] = []
    for path in sorted(package_dir.rglob("*.xml")):
        if not path.is_file():
            continue
        try:
            content = path.read_bytes()
        except OSError:
            continue
        if _looks_like_oval_bytes(content):
            matches.append(path)
    return matches


def detect_package_format(package_dir: Path) -> str:
    """Return 'custom', 'xccdf', or 'oval'. Raises ValueError for unrecognized uploads."""
    if _find_profile_file(package_dir) is not None:
        return "custom"

    xccdf_files = find_xccdf_files(package_dir)
    if xccdf_files:
        return "xccdf"

    oval_files = find_oval_only_files(package_dir)
    if oval_files:
        return "oval"

    raise ValueError(
        "Unrecognized profile package. Expected custom description.json "
        "ZIP/files, an XCCDF Benchmark / SCAP data-stream, "
        "or an OVAL definitions XML."
    )


def _gather_sibling_content(package_dir: Path, benchmark_file: Path) -> list[tuple[str, bytes]]:
    """Collect sibling OVAL/CPE XML files that a benchmark may reference via check-content-ref."""
    extra: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for path in sorted(package_dir.rglob("*.xml")):
        if not path.is_file() or path == benchmark_file:
            continue
        name = path.name
        if name in seen or name in ("scap_benchmark.xml", DESCRIPTION_FILE):
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        # Only carry SCAP content (OVAL/CPE); skip unrelated benchmarks.
        if _looks_like_xccdf_bytes(data) and not _looks_like_oval_bytes(data):
            continue
        extra.append((name, data))
        seen.add(name)
    return extra


def convert_xccdf_package_dir(package_dir: Path, *, scap_profile_id: str | None = None) -> Path:
    """Parse first XCCDF/data-stream in package_dir and materialize synthetic package."""
    xccdf_files = find_xccdf_files(package_dir)
    if not xccdf_files:
        raise ValueError("No XCCDF Benchmark XML found in upload")

    benchmark_file = xccdf_files[0]
    content = benchmark_file.read_bytes()
    if _looks_like_oval_bytes(content) and not _looks_like_xccdf_bytes(content):
        raise ValueError("Expected XCCDF Benchmark but found OVAL-only content")

    benchmark = parse_xccdf_xml(content)
    profiles = parse_xccdf_profiles(content)
    profile_title = None
    profile_family = infer_scap_profile_family(benchmark)
    if scap_profile_id:
        matched = next((item for item in profiles if item.profile_id == scap_profile_id), None)
        if matched is None and profiles:
            raise ValueError(f"XCCDF profile not found: {scap_profile_id}")
        if matched:
            profile_title = matched.title
            profile_family = infer_scap_profile_family(benchmark, matched)
    extra_files = _gather_sibling_content(package_dir, benchmark_file)
    out_dir = package_dir / "_secaudit_xccdf_package"
    if out_dir.exists():
        for child in out_dir.iterdir():
            if child.is_file():
                child.unlink()
    materialize_xccdf_package(
        benchmark,
        out_dir,
        xccdf_bytes=content,
        extra_files=extra_files,
        scap_profile_id=scap_profile_id,
        profile_title=profile_title,
        profile_family=profile_family,
    )
    return out_dir


def _oval_rule_check_lines(mnemonic: str, def_id: str, title: str) -> list[str]:
    safe_title = title.replace('"', "'")
    return [
        f'_OVAL_DEF="{def_id}"',
        'if command -v oscap >/dev/null 2>&1 && [ -f "scap_oval.xml" ]; then',
        "  _OVAL_RES=$(mktemp)",
        '  if oscap oval eval --id "$_OVAL_DEF" --results "$_OVAL_RES" scap_oval.xml >/dev/null 2>&1; then',
        f'    if grep -q \'result="true"\' "$_OVAL_RES" 2>/dev/null; then',
        f'      echo "{mnemonic}= PASS: {safe_title} (oval)"',
        "    else",
        f'      echo "{mnemonic}= FAIL: {safe_title} (oval)"',
        "    fi",
        "  else",
        f'    echo "{mnemonic}= SKIP: oval eval failed for {def_id}"',
        "  fi",
        '  rm -f "$_OVAL_RES"',
        "else",
        f'  echo "{mnemonic}= SKIP: install oscap on target to evaluate OVAL {def_id}"',
        "fi",
    ]


def materialize_oval_package(
    oval: OvalDocument,
    dest: Path,
    *,
    oval_bytes: bytes,
) -> Path:
    """Materialize a SecAudit package for standalone OVAL definitions."""
    dest.mkdir(parents=True, exist_ok=True)
    tech_name = _safe_slug(oval.oval_id or oval.title, max_len=120)
    script_stem = _safe_slug(tech_name, max_len=60) + "_scripts"

    os_meta = {"name": "Linux", "vendor": "OVAL / MITRE", "version": "", "icon": "ic_linux.svg"}
    software_meta = {
        "name": oval.title[:200],
        "vendor": "OVAL / MITRE",
        "category": "SCAP / OVAL",
        "version": oval.version,
    }
    (dest / "scap_oval.xml").write_bytes(oval_bytes)

    profile_meta = {
        "profile_name": tech_name,
        "is_active": True,
        "version": oval.version or "1.0",
        "overview": f"Imported from OVAL definitions ({len(oval.definitions)} definitions)"[:2000],
        "os": os_meta,
        "software": software_meta,
        "encoding": "utf-8",
        "profile_rules": PROFILE_RULES_JSON,
        "source_format": "oval",
        "scap_oval_path": "scap_oval.xml",
        "scap_oval_id": oval.oval_id,
        "category_slug": "linux-platform",
    }
    (dest / DESCRIPTION_FILE).write_text(
        json.dumps(profile_meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    rules_records: list[dict] = []
    audit_lines = [
        "#!/bin/bash",
        f"# Auto-generated from OVAL definitions: {oval.oval_id}",
        "# OVAL definitions are evaluated via the worker OpenSCAP executor (oscap oval eval); "
        "per-definition oscap below is a fallback for SSH-script jobs.",
        "export LC_ALL=C",
        'cd "$(dirname "$0")" 2>/dev/null || true',
        "",
    ]

    for index, definition in enumerate(oval.definitions, start=1):
        mnemonic = _req_mnemonic(index)
        context = _req_context(index)
        title = _csv_escape_field(definition.title)[:500]
        description = _csv_escape_field(definition.description)[:4000]
        rules_records.append(
            {
                "num": str(index),
                "title": title,
                "explanation": description,
                "impact": definition.definition_class,
                "criticality": "INFO",
                "check_script": script_stem,
                "requirement_id": context,
                "match_pattern": f"{mnemonic}=(.*)",
                "scap_rule_id": definition.definition_id,
            }
        )
        audit_lines.extend(_oval_rule_check_lines(mnemonic, definition.definition_id, title))
        audit_lines.append("")

    _write_profile_rules_json(dest, rules_records)
    script_path = dest / f"{script_stem}.sh"
    script_path.write_text("\n".join(audit_lines) + "\n", encoding="utf-8")
    script_path.chmod(script_path.stat().st_mode | 0o111)
    return dest


def convert_oval_package_dir(package_dir: Path) -> Path:
    """Parse first OVAL-only file in package_dir and materialize a synthetic package."""
    oval_files = find_oval_only_files(package_dir)
    if not oval_files:
        raise ValueError("No OVAL definitions XML found in upload")

    content = oval_files[0].read_bytes()
    oval = parse_oval_xml(content)
    out_dir = package_dir / "_secaudit_oval_package"
    if out_dir.exists():
        for child in out_dir.iterdir():
            if child.is_file():
                child.unlink()
    materialize_oval_package(oval, out_dir, oval_bytes=content)
    return out_dir


def prepare_upload_package(
    package_dir: Path,
    *,
    scap_profile_id: str | None = None,
) -> tuple[Path, str]:
    """Detect upload type and materialize a synthetic SecAudit package when needed.

    Returns (package_dir, source_format) where source_format is 'custom' | 'xccdf' | 'oval'.
    """
    fmt = detect_package_format(package_dir)
    if fmt == "custom":
        return package_dir, "custom"
    if fmt == "oval":
        return convert_oval_package_dir(package_dir), "oval"
    return convert_xccdf_package_dir(package_dir, scap_profile_id=scap_profile_id), "xccdf"


def preview_xccdf_profiles_from_uploads(uploads: list[tuple[str, bytes]]) -> list[dict]:
    """Return available XCCDF profiles from uploaded SCAP content (for import UI)."""
    profiles: list[dict] = []
    seen: set[str] = set()
    for filename, content in uploads:
        lowered = filename.lower()
        if not lowered.endswith((".xml", ".xccdf", ".zip")):
            continue
        try:
            if lowered.endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(content)) as archive:
                    for name in archive.namelist():
                        if not name.lower().endswith((".xml", ".xccdf")):
                            continue
                        data = archive.read(name)
                        if not _looks_like_xccdf_bytes(data):
                            continue
                        benchmark = parse_xccdf_xml(data)
                        family = infer_scap_profile_family(benchmark)
                        for profile in parse_xccdf_profiles(data):
                            if profile.profile_id in seen:
                                continue
                            seen.add(profile.profile_id)
                            profiles.append(
                                {
                                    "profile_id": profile.profile_id,
                                    "title": profile.title,
                                    "description": profile.description,
                                    "benchmark_title": benchmark.title,
                                    "profile_family": infer_scap_profile_family(benchmark, profile),
                                }
                            )
            else:
                if not _looks_like_xccdf_bytes(content):
                    continue
                benchmark = parse_xccdf_xml(content)
                for profile in parse_xccdf_profiles(content):
                    if profile.profile_id in seen:
                        continue
                    seen.add(profile.profile_id)
                    profiles.append(
                        {
                            "profile_id": profile.profile_id,
                            "title": profile.title,
                            "description": profile.description,
                            "benchmark_title": benchmark.title,
                            "profile_family": infer_scap_profile_family(benchmark, profile),
                        }
                    )
        except ValueError:
            continue
    return profiles


def parse_xccdf_from_uploads_preview(filename: str, content: bytes) -> XccdfBenchmark:
    """Helper for tests / diagnostics: parse raw upload bytes without full package IO."""
    lowered = filename.lower()
    if lowered.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            for name in archive.namelist():
                if name.lower().endswith((".xml", ".xccdf")):
                    data = archive.read(name)
                    if _looks_like_xccdf_bytes(data):
                        return parse_xccdf_xml(data)
        raise ValueError("ZIP archive does not contain an XCCDF Benchmark XML")
    if lowered.endswith((".xml", ".xccdf")):
        if _looks_like_oval_bytes(content) and not _looks_like_xccdf_bytes(content):
            raise ValueError(
                "This is an OVAL-only document; import it directly to use the OVAL evaluator."
            )
        return parse_xccdf_xml(content)
    raise ValueError(f"Unsupported SCAP upload filename: {filename}")
