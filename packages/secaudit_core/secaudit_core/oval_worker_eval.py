"""Limited worker-side OVAL evaluation from remotely collected facts.

Used when the target has no ``oscap``. Supports a practical subset of OVAL
objects collected over SSH (packages, files, sysctl, uname) and maps each
definition to ``true`` / ``false`` / ``unknown`` compatible with
``parse_oval_results_xml`` consumers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from defusedxml import ElementTree as DefusedET

_PACKAGE_BLOCK = "###SECAUDIT_PACKAGES###"
_SYSCTL_BLOCK = "###SECAUDIT_SYSCTL###"
_UNAME_BLOCK = "###SECAUDIT_UNAME###"
_FILES_BLOCK = "###SECAUDIT_FILES###"


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


@dataclass
class OvalProbePlan:
    packages: set[str] = field(default_factory=set)
    files: set[str] = field(default_factory=set)
    sysctl_keys: set[str] = field(default_factory=set)
    need_uname: bool = False
    definition_ids: list[str] = field(default_factory=list)
    # definition_id -> list of simple requirements
    requirements: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


def build_probe_plan(oval_xml: bytes) -> OvalProbePlan:
    """Extract collectable probes and per-definition requirements from OVAL XML."""
    root = DefusedET.fromstring(oval_xml)
    plan = OvalProbePlan()

    objects: dict[str, dict[str, Any]] = {}
    for node in root.iter():
        name = _local_name(node.tag).lower()
        obj_id = (node.get("id") or "").strip()
        if not obj_id:
            continue
        if name in {"file_object", "textfilecontent54_object", "textfilecontent_object"}:
            path = _child_text(node, "path") or _child_text(node, "filepath") or ""
            filename = _child_text(node, "filename") or ""
            filepath = path
            if filename and path:
                filepath = f"{path.rstrip('/')}/{filename.lstrip('/')}"
            elif _child_text(node, "filepath"):
                filepath = _child_text(node, "filepath") or ""
            if filepath:
                objects[obj_id] = {"type": "file", "path": filepath}
                plan.files.add(filepath)
        elif name in {"rpminfo_object", "dpkginfo_object", "rpminfo_state"}:
            pkg = _child_text(node, "name") or ""
            if pkg:
                objects[obj_id] = {"type": "package", "name": pkg}
                plan.packages.add(pkg)
        elif name in {"sysctl_object"}:
            key = _child_text(node, "name") or ""
            if key:
                objects[obj_id] = {"type": "sysctl", "name": key}
                plan.sysctl_keys.add(key)
        elif name in {"uname_object"}:
            objects[obj_id] = {"type": "uname"}
            plan.need_uname = True

    tests: dict[str, dict[str, Any]] = {}
    for node in root.iter():
        name = _local_name(node.tag).lower()
        test_id = (node.get("id") or "").strip()
        if not test_id or "test" not in name:
            continue
        obj_ref = ""
        for child in list(node):
            if _local_name(child.tag).lower() in {"object", "object_ref"}:
                obj_ref = (child.get("object_ref") or child.get("idref") or child.text or "").strip()
                if obj_ref:
                    break
        check_existence = (node.get("check_existence") or "at_least_one_exists").strip().lower()
        if obj_ref:
            tests[test_id] = {
                "object_ref": obj_ref,
                "check_existence": check_existence,
                "object": objects.get(obj_ref),
            }

    for node in root.iter():
        if _local_name(node.tag).lower() != "definition":
            continue
        def_id = (node.get("id") or "").strip()
        if not def_id:
            continue
        plan.definition_ids.append(def_id)
        reqs: list[dict[str, Any]] = []
        for child in node.iter():
            if _local_name(child.tag).lower() != "criterion":
                continue
            test_ref = (child.get("test_ref") or "").strip()
            test = tests.get(test_ref)
            if not test or not test.get("object"):
                continue
            reqs.append(test["object"] | {"check_existence": test["check_existence"]})
        plan.requirements[def_id] = reqs

    return plan


def _child_text(node, local: str) -> str | None:
    for child in list(node):
        if _local_name(child.tag).lower() == local.lower():
            text = (child.text or "").strip()
            return text or None
    return None


def build_fact_collection_script(plan: OvalProbePlan) -> str:
    """Shell script that dumps facts for the probe plan (bash/POSIX-ish)."""
    lines = [
        "#!/bin/sh",
        "set +e",
        f"echo {_PACKAGE_BLOCK}",
        "if command -v rpm >/dev/null 2>&1; then",
        "  rpm -qa --qf '%{NAME}\\t%{EPOCH}:%{VERSION}-%{RELEASE}\\n' 2>/dev/null",
        "elif command -v dpkg-query >/dev/null 2>&1; then",
        "  dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null",
        "fi",
        f"echo {_SYSCTL_BLOCK}",
        "sysctl -a 2>/dev/null",
        f"echo {_UNAME_BLOCK}",
        "uname -a 2>/dev/null",
        f"echo {_FILES_BLOCK}",
    ]
    for path in sorted(plan.files):
        safe = path.replace("'", "'\\''")
        lines.append(f"if [ -e '{safe}' ]; then echo PRESENT\\t{safe}; else echo MISSING\\t{safe}; fi")
    lines.append("exit 0")
    return "\n".join(lines) + "\n"


@dataclass
class CollectedFacts:
    packages: dict[str, str] = field(default_factory=dict)  # name -> version
    sysctl: dict[str, str] = field(default_factory=dict)
    files_present: set[str] = field(default_factory=set)
    uname: str = ""


def parse_fact_collection_output(output: str) -> CollectedFacts:
    facts = CollectedFacts()
    section = ""
    for raw in (output or "").splitlines():
        line = raw.rstrip("\n")
        if line in {_PACKAGE_BLOCK, _SYSCTL_BLOCK, _UNAME_BLOCK, _FILES_BLOCK}:
            section = line
            continue
        if section == _PACKAGE_BLOCK:
            if "\t" in line:
                name, version = line.split("\t", 1)
                if name.strip():
                    facts.packages[name.strip()] = version.strip()
        elif section == _SYSCTL_BLOCK:
            match = re.match(r"^([^=]+)=\s*(.*)$", line)
            if match:
                facts.sysctl[match.group(1).strip()] = match.group(2).strip()
        elif section == _UNAME_BLOCK:
            if line.strip():
                facts.uname = line.strip()
        elif section == _FILES_BLOCK:
            if line.startswith("PRESENT\t"):
                facts.files_present.add(line.split("\t", 1)[1])
    return facts


def _requirement_holds(req: dict[str, Any], facts: CollectedFacts) -> bool | None:
    """True/False when evaluable; None when the object type is unsupported."""
    rtype = req.get("type")
    if rtype == "file":
        path = str(req.get("path") or "")
        exists = path in facts.files_present
        check = str(req.get("check_existence") or "at_least_one_exists")
        if check == "none_exist":
            return not exists
        return exists
    if rtype == "package":
        return str(req.get("name") or "") in facts.packages
    if rtype == "sysctl":
        return str(req.get("name") or "") in facts.sysctl
    if rtype == "uname":
        return bool(facts.uname)
    return None


def evaluate_definitions(plan: OvalProbePlan, facts: CollectedFacts) -> dict[str, str]:
    """Return OVAL-style results: definition_id -> true|false|unknown."""
    outcomes: dict[str, str] = {}
    for def_id in plan.definition_ids:
        reqs = plan.requirements.get(def_id) or []
        if not reqs:
            outcomes[def_id] = "unknown"
            continue
        values: list[bool] = []
        unknown = False
        for req in reqs:
            held = _requirement_holds(req, facts)
            if held is None:
                unknown = True
                break
            values.append(held)
        if unknown or not values:
            outcomes[def_id] = "unknown"
        else:
            outcomes[def_id] = "true" if all(values) else "false"
    return outcomes
