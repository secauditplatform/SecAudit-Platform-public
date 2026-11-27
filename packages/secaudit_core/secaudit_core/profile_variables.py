"""Typed profile parameters declared in a package ``variables.json``.

Resolution is package default, then the values frozen on a profile version.
A missing version uses the package defaults, so a profile without versions
keeps the check behavior shipped in the package.
"""

from __future__ import annotations

import json
import re
from html import escape as xml_escape
from pathlib import Path

NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,40}$")
RULE_RE = re.compile(r"^RULE0*(\d+)$")
VARIABLE_TYPES = frozenset({"int", "string", "bool", "enum"})


def load_package_variables(package_dir: Path) -> list[dict]:
    path = package_dir / "variables.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path.name}: {exc}") from exc
    raw = data.get("variables") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        raise ValueError(f"{path.name} must contain a variables list")
    declarations = [normalize_declaration(item) for item in raw]
    seen_names: set[str] = set()
    seen_rules: set[str] = set()
    for item in declarations:
        if item["name"] in seen_names:
            raise ValueError(f"duplicate variable {item['name']}")
        seen_names.add(item["name"])
        for rule_id in item["requirement_ids"]:
            if rule_id in seen_rules:
                raise ValueError(f"{rule_id} is bound to more than one variable")
            seen_rules.add(rule_id)
    return declarations


def normalize_declaration(item: object) -> dict:
    if not isinstance(item, dict):
        raise ValueError("variable entry must be an object")
    name = str(item.get("name") or "").strip()
    if not NAME_RE.fullmatch(name):
        raise ValueError(f"invalid variable name {name!r}")
    kind = str(item.get("type") or "").strip()
    if kind not in VARIABLE_TYPES:
        raise ValueError(f"{name}: type must be int, string, bool, or enum")
    enum = item.get("enum")
    if kind == "enum":
        if not isinstance(enum, list) or not enum or not all(isinstance(v, str) and v for v in enum):
            raise ValueError(f"{name}: enum needs a list of strings")
    else:
        enum = None
    default = coerce_variable(name, kind, item.get("default"), enum=enum, bounds=item)
    minimum = _optional_int(item.get("min"), f"{name} min")
    maximum = _optional_int(item.get("max"), f"{name} max")
    if kind == "int":
        _check_bounds(name, default, minimum, maximum)
    requirement_ids = _requirement_ids(item.get("requirement_ids"))
    xccdf = item.get("xccdf_value_id")
    xccdf_value_id = str(xccdf).strip() if isinstance(xccdf, str) and xccdf.strip() else None
    description = item.get("description")
    return {
        "name": name,
        "type": kind,
        "default": default,
        "min": minimum,
        "max": maximum,
        "enum": enum,
        "description": str(description).strip() if isinstance(description, str) else "",
        "requirement_ids": requirement_ids,
        "xccdf_value_id": xccdf_value_id,
    }


def resolve_profile_variables(schema: object, overrides: object | None) -> list[dict]:
    """Return the values a run must use. Unknown override names are rejected."""
    declarations = _schema_list(schema)
    provided = overrides if isinstance(overrides, dict) else {}
    unknown = sorted(str(key) for key in provided if str(key) not in {item["name"] for item in declarations})
    if unknown:
        raise ValueError(f"unknown variable {unknown[0]}")
    resolved: list[dict] = []
    for item in declarations:
        raw = provided[item["name"]] if item["name"] in provided else item["default"]
        value = coerce_variable(
            item["name"],
            item["type"],
            raw,
            enum=item.get("enum"),
            bounds=item,
        )
        resolved.append(
            {
                "name": item["name"],
                "type": item["type"],
                "value": value,
                "requirement_ids": list(item["requirement_ids"]),
                "xccdf_value_id": item.get("xccdf_value_id"),
            }
        )
    return resolved


def variable_env_for(profile, version=None) -> dict[str, str]:
    schema = getattr(profile, "variable_schema", None) or []
    overrides = getattr(version, "variable_values", None) if version is not None else None
    try:
        resolved = resolve_profile_variables(schema, overrides)
    except ValueError:
        resolved = resolve_profile_variables(schema, None)
    return env_from_resolved(resolved)


def env_from_resolved(resolved: list[dict]) -> dict[str, str]:
    env: dict[str, str] = {}
    for item in resolved:
        text = _env_text(item["value"])
        env[f"SECAUDIT_VAR_{item['name']}"] = text
        for rule_id in item["requirement_ids"]:
            for key in _rule_env_names(rule_id):
                env[key] = text
    return env


def snapshot_variables(profile, version=None) -> list[dict]:
    schema = getattr(profile, "variable_schema", None) or []
    overrides = getattr(version, "variable_values", None) if version is not None else None
    try:
        resolved = resolve_profile_variables(schema, overrides)
    except ValueError:
        resolved = resolve_profile_variables(schema, None)
    return [
        {
            "name": item["name"],
            "value": item["value"],
            "requirement_ids": item["requirement_ids"],
        }
        for item in resolved
    ]


def build_tailoring_xml(resolved: list[dict], *, profile_id: str | None) -> str | None:
    """XCCDF tailoring for variables that name an ``xccdf_value_id``. None when unused."""
    if not profile_id:
        return None
    selected = [item for item in resolved if item.get("xccdf_value_id")]
    if not selected:
        return None
    rows = "\n".join(
        f'    <xccdf:set-value idref="{xml_escape(str(item["xccdf_value_id"]), quote=True)}">'
        f"{xml_escape(str(item['value']))}</xccdf:set-value>"
        for item in selected
    )
    extends = xml_escape(profile_id, quote=True)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<xccdf:Tailoring xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" id="secaudit-tailoring">\n'
        f'  <xccdf:Profile id="secaudit_tailored" extends="{extends}">\n'
        f"{rows}\n"
        "  </xccdf:Profile>\n"
        "</xccdf:Tailoring>\n"
    )


def coerce_variable(name: str, kind: str, raw: object, *, enum, bounds: dict) -> object:
    if kind == "int":
        value = _as_int(raw, name)
        _check_bounds(name, value, _optional_int(bounds.get("min"), f"{name} min"), _optional_int(bounds.get("max"), f"{name} max"))
        return value
    if kind == "bool":
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str) and raw.strip().lower() in {"true", "false"}:
            return raw.strip().lower() == "true"
        raise ValueError(f"{name} must be true or false")
    if kind == "enum":
        text = str(raw).strip() if raw is not None else ""
        if text not in (enum or []):
            raise ValueError(f"{name} must be one of {', '.join(enum or [])}")
        return text
    if raw is None:
        raise ValueError(f"{name} is required")
    return str(raw)


def _schema_list(schema: object) -> list[dict]:
    if not schema:
        return []
    if not isinstance(schema, list):
        raise ValueError("variable schema must be a list")
    return [normalize_declaration(item) for item in schema]


def _requirement_ids(raw: object) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("requirement_ids must be a list")
    ids: list[str] = []
    for item in raw:
        text = str(item).strip().upper()
        if not text:
            continue
        if text.isdigit():
            text = f"RULE{int(text)}"
        ids.append(text)
    return list(dict.fromkeys(ids))


def _as_int(raw: object, name: str) -> int:
    if isinstance(raw, bool) or raw is None:
        raise ValueError(f"{name} must be an integer")
    if isinstance(raw, int):
        return raw
    text = str(raw).strip()
    if not re.fullmatch(r"-?\d+", text):
        raise ValueError(f"{name} must be an integer")
    return int(text)


def _optional_int(raw: object, label: str) -> int | None:
    if raw is None or raw == "":
        return None
    return _as_int(raw, label)


def _check_bounds(name: str, value: int, minimum: int | None, maximum: int | None) -> None:
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be at most {maximum}")


def _env_text(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _rule_env_names(requirement_id: str) -> list[str]:
    raw = requirement_id.strip().upper()
    names = [f"SECAUDIT_VAR_{raw}"]
    match = RULE_RE.fullmatch(raw)
    if match:
        plain = f"SECAUDIT_VAR_RULE{int(match.group(1))}"
        if plain not in names:
            names.append(plain)
    return names
