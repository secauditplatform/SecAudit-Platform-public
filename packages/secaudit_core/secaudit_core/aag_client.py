"""One OpenAI-compatible chat client for the internal and external AAG providers.

The operator fragment is redacted before the provider is chosen. The API key
is sent only as a request header for the external provider and is stripped
from any error text. This module does not read or write check results.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import httpx

from secaudit_core.sensitive_data import REDACTED, redact_sensitive
from secaudit_core.url_safety import UnsafeOutboundURLError, validate_outbound_webhook_url

TASK_KINDS = ("explain", "generate")
AAG_MAX_TIMEOUT_SECONDS = 120 * 60
DRAFT_TYPES = ("waiver", "remediation_plan", "audit_flow", "network", "playbook", "mapping")
HOST_FILTER_KEYS = ("site", "environment", "tag", "os_type", "criticality", "active_only")
MAX_FINDINGS = 25
_OFFICIAL_MARKERS = ("cis", "stig", "fstek", "fstec", "фстэк")

_SYSTEM_PROMPTS = {
    "explain": (
        "Reply with one JSON object and no other text. "
        '{"checks":[{"rule":"","host":"","status":"","what":"","checked":"","did":""}]} '
        "One object per finding in the input, in the same order. "
        "what: one sentence naming the control from its title. "
        "checked: one sentence on the condition it verifies, from rule_text only. "
        "did: one or two sentences on what the check did in this run and what it recorded, "
        "citing run_id=<id> and rule=<rule>. "
        "Copy status from the input. Do not change PASS, FAIL, ERROR, or SKIP. "
        "Do not add a check that is not in the input."
    ),
    "generate": (
        "Reply with one JSON object and no other text. Keys: description, rules, script_name, script. "
        "description needs profile_name, version, and an os or software object with name, vendor, and version. "
        "os and software are objects, not file names. "
        "description.profile_family must be custom, benchmark_ref empty, source_format custom. "
        "Do not sign the package as CIS, STIG, or FSTEK. "
        "rules.format must be secaudit.profile_rules. Each rule needs requirement_id, title, "
        "explanation, criticality, check_script, and match_pattern. "
        "The script prints RULE0001=PASS style lines for every rule. "
        "Copy every operator line that is present. Do not replace those values. "
        "Fill every omitted field from the request: version, os or software, overview, and purpose. "
        "Name the check script check.sh, check.ps1, or check.py, and set check_script to check. "
        "If the request does not describe checks for one custom profile, reply with "
        '{"error": "The request did not describe any checks"} and an empty rules list.'
    ),
}


class AagClientError(Exception):
    """Provider call failed. The message never contains the API key."""

    def __init__(self, message: str, *, error_code: str | None = None) -> None:
        super().__init__(message)
        code = "".join(ch for ch in (error_code or "") if ch.isalnum() or ch == "_")[:32]
        self.error_code = code or None


class AagChatResult:
    """Model text plus a token count. The count is a number, never the prompt."""

    def __init__(self, text: str, token_count: int | None = None) -> None:
        self.text = text
        self.token_count = token_count


def system_prompt(kind: str) -> str:
    prompt = _SYSTEM_PROMPTS.get(kind)
    if prompt is None:
        raise AagClientError("Unknown AAG task")
    return prompt


def redact_fragment(text: str) -> str:
    """Redact secrets before any provider is selected."""
    cleaned = redact_sensitive(text or "")
    return cleaned if isinstance(cleaned, str) else ""


def citation_payload(
    *,
    run_id: int | None = None,
    rule_tech_name: str | None = None,
    host_id: int | None = None,
) -> dict[str, Any] | None:
    """Refs the screen already chose. No raw check output is added."""
    payload: dict[str, Any] = {}
    if run_id is not None:
        payload["run_id"] = run_id
    rule = (rule_tech_name or "").strip()
    if rule:
        payload["rule_tech_name"] = rule
    if host_id is not None:
        payload["host_id"] = host_id
    return payload or None


def input_hash(kind: str, redacted: str, citation: Mapping[str, Any] | None) -> str:
    body = json.dumps(
        {"kind": kind, "prompt": redacted, "citation": dict(citation or {})},
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def chat_completions_url(base_url: str) -> str:
    cleaned = base_url.rstrip("/")
    if cleaned.endswith("/v1"):
        return f"{cleaned}/chat/completions"
    return f"{cleaned}/v1/chat/completions"


def safe_provider_error(exc: BaseException, api_key: str | None) -> str:
    text = redact_sensitive(str(exc))
    if not isinstance(text, str) or not text.strip():
        text = "Provider request failed"
    if api_key:
        text = text.replace(api_key, REDACTED)
    return text[:500]


def provider_status_error(payload: Any, api_key: str | None) -> str:
    """HTTP error text safe to store. The key and other secrets are stripped."""
    detail = ""
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            message = error.get("message")
            if isinstance(message, str):
                detail = message.strip()
        elif isinstance(error, str):
            detail = error.strip()
    cleaned = safe_provider_error(Exception(detail), api_key) if detail else ""
    if not cleaned or cleaned == REDACTED or api_key and api_key in cleaned:
        return "Provider returned an error"
    return f"Provider returned an error: {cleaned}"[:500]


def _user_content(redacted: str, citation: Mapping[str, Any] | None) -> str:
    if not citation:
        return redacted
    lines = [redacted, "", "Cited by the operator:"]
    if "run_id" in citation:
        lines.append(f"run_id={citation['run_id']}")
    if citation.get("rule_tech_name"):
        lines.append(f"rule={citation['rule_tech_name']}")
    if "host_id" in citation:
        lines.append(f"host_id={citation['host_id']}")
    return "\n".join(lines)


def _token_count(payload: Any) -> int | None:
    if not isinstance(payload, dict):
        return None
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        return None
    total = usage.get("total_tokens")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        return None
    return total


def _read_completion(payload: Any) -> str:
    if not isinstance(payload, dict):
        raise AagClientError("Provider response was not a chat completion")
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise AagClientError("Provider response was not a chat completion")
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str) or not content.strip():
        raise AagClientError("Provider response was empty", error_code="empty")
    return content.strip()


def complete_chat(
    *,
    provider: str,
    base_url: str,
    model: str,
    fragment: str,
    kind: str,
    api_key: str | None = None,
    timeout_seconds: int = 30,
    max_tokens: int = 2000,
    retry_on_network_error: bool = True,
    allow_private: bool = False,
    citation: Mapping[str, Any] | None = None,
) -> AagChatResult:
    """Call the configured provider. ``fragment`` is redacted before the request."""
    if provider not in {"internal", "external"}:
        raise AagClientError("AAG provider is not configured")
    redacted = redact_fragment(fragment)
    if not redacted.strip():
        raise AagClientError("Task text is empty")
    model_name = (model or "").strip()
    if not model_name:
        raise AagClientError("Model name is required")

    try:
        safe_url = validate_outbound_webhook_url(
            base_url,
            allow_http=provider == "internal",
            allow_private=True if provider == "internal" else allow_private,
        )
    except UnsafeOutboundURLError as exc:
        raise AagClientError(str(exc)) from None
    url = chat_completions_url(safe_url)
    headers = {"Content-Type": "application/json"}
    if provider == "external":
        key = (api_key or "").strip()
        if not key:
            raise AagClientError("External provider has no API key")
        headers["Authorization"] = f"Bearer {key}"
    else:
        key = None

    body = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_prompt(kind)},
            {"role": "user", "content": _user_content(redacted, citation)},
        ],
        "max_tokens": max_tokens,
    }
    attempts = 2 if retry_on_network_error else 1
    timeout = max(1, min(int(timeout_seconds or 30), AAG_MAX_TIMEOUT_SECONDS))
    last_error: AagClientError | None = None
    for attempt in range(attempts):
        try:
            with httpx.Client(timeout=timeout, follow_redirects=False) as client:
                response = client.post(url, json=body, headers=headers)
            if response.status_code >= 400:
                try:
                    error_payload = response.json()
                except Exception:
                    error_payload = None
                raise AagClientError(
                    provider_status_error(error_payload, key),
                    error_code=f"http_{response.status_code}",
                )
            try:
                payload = response.json()
            except Exception:
                raise AagClientError("Provider response was not a chat completion", error_code="invalid_response") from None
            return AagChatResult(text=_read_completion(payload), token_count=_token_count(payload))
        except AagClientError:
            raise
        except httpx.TimeoutException as exc:
            raise AagClientError(safe_provider_error(exc, key), error_code="timeout") from None
        except httpx.TransportError as exc:
            code = "timeout" if isinstance(exc, httpx.TimeoutException) else "network"
            last_error = AagClientError(safe_provider_error(exc, key), error_code=code)
            if attempt + 1 >= attempts:
                raise last_error from None
        except Exception as exc:
            raise AagClientError(safe_provider_error(exc, key)) from None
    raise last_error or AagClientError("Provider request failed")


def build_explain_fragment(findings: list[Mapping[str, Any]], *, run_id: int) -> str:
    """Facts the screen already stored. Raw command output is never included."""
    lines = [f"run_id={run_id}", "Findings:"]
    for item in findings[:MAX_FINDINGS]:
        rule = str(item.get("rule_tech_name") or "").strip()
        host = str(item.get("host_name") or item.get("host_id") or "").strip()
        os_type = str(item.get("os_type") or "").strip()
        status = str(item.get("status") or "").strip()
        title = str(item.get("rule_title") or "").strip()
        message = str(item.get("message") or "").strip()
        rule_text = str(item.get("rule_text") or "").strip()
        ready = "yes" if item.get("has_remediation") else "no"
        parts = [f"rule={rule}", f"status={status}", f"host={host}", f"os={os_type}"]
        if title:
            parts.append(f"title={title}")
        parts.append(f"remediation_script={ready}")
        parts.append(f"message={message}")
        lines.append("; ".join(parts))
        if rule_text:
            lines.append(f"rule_text={rule_text}")
    return redact_fragment("\n".join(lines))[:12000]


def parse_explain_sections(raw: str) -> list[dict[str, Any]]:
    """Structured explanation. An ordinary paragraph reply stays a paragraph."""
    items = _json_object(raw).get("checks")
    if not isinstance(items, list):
        return []
    sections: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        what = str(item.get("what") or "").strip()
        checked = str(item.get("checked") or "").strip()
        did = str(item.get("did") or "").strip()
        if not (what or checked or did):
            continue
        sections.append(
            {
                "rule": str(item.get("rule") or "").strip(),
                "host": str(item.get("host") or "").strip(),
                "status": str(item.get("status") or "").strip(),
                "what": what,
                "checked": checked,
                "did": did,
            }
        )
    return sections


def explain_section_confirmed(
    section: Mapping[str, Any],
    *,
    run_id: int | None,
    rules: list[str],
) -> bool:
    """The recorded part is confirmed only when it cites the run and a rule."""
    text = str(section.get("did") or "")
    lowered = text.lower()
    has_run = run_id is not None and str(run_id) in text and "run" in lowered
    known = [rule.strip() for rule in rules if rule and rule.strip()]
    rule = str(section.get("rule") or "").strip()
    pool = known or ([rule] if rule else [])
    has_rule = any(item.lower() in lowered for item in pool) if pool else "rule=" in lowered
    return bool(has_run and has_rule)


def annotate_paragraphs(
    text: str,
    *,
    run_id: int | None,
    rules: list[str],
) -> list[dict[str, Any]]:
    """A paragraph is confirmed only when it cites the run and a rule."""
    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", text or "") if part.strip()]
    if not paragraphs and (text or "").strip():
        paragraphs = [(text or "").strip()]
    known = [rule.strip() for rule in rules if rule and rule.strip()]
    marked: list[dict[str, Any]] = []
    for paragraph in paragraphs:
        lowered = paragraph.lower()
        has_run = run_id is not None and str(run_id) in paragraph and "run" in lowered
        has_rule = any(rule.lower() in lowered for rule in known) if known else "rule=" in lowered
        marked.append({"text": paragraph, "confirmed": bool(has_run and has_rule)})
    return marked


def parse_host_filter(raw: str) -> dict[str, Any]:
    """Keep only fields GET /hosts already accepts. Drop host lists and other keys."""
    text = (raw or "").strip()
    payload: Any = None
    if text:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                try:
                    payload = json.loads(match.group(0))
                except json.JSONDecodeError:
                    payload = None
    if not isinstance(payload, dict):
        return {}
    cleaned: dict[str, Any] = {}
    for key in ("site", "environment", "tag", "os_type", "criticality"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            cleaned[key] = value.strip()
    if payload.get("active_only") is True:
        cleaned["active_only"] = True
    return cleaned


def _json_object(raw: str) -> dict[str, Any]:
    text = (raw or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text).strip()
        text = re.sub(r"```$", "", text).strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return {}
        try:
            payload = json.loads(match.group(0))
        except json.JSONDecodeError:
            return {}
    return payload if isinstance(payload, dict) else {}


def official_benchmark_name(name: str) -> bool:
    lowered = (name or "").lower()
    return any(marker in lowered for marker in _OFFICIAL_MARKERS)


def _safe_match_pattern(requirement_id: str, pattern: str) -> str:
    candidate = (pattern or "").strip() or f"{requirement_id}=(.*)"
    try:
        re.compile(candidate)
    except re.error:
        candidate = re.escape(requirement_id) + "=(.*)"
    return candidate


def _completed_rules(raw_rules: list[Any], stem: str) -> list[dict[str, str]]:
    completed: list[dict[str, str]] = []
    for index, item in enumerate(raw_rules, start=1):
        if not isinstance(item, dict):
            continue
        requirement_id = str(
            item.get("requirement_id") or item.get("tech_name") or item.get("id") or f"RULE{index:04d}"
        ).strip()
        if not requirement_id:
            continue
        title = str(item.get("title") or item.get("summary") or requirement_id).strip() or requirement_id
        explanation = str(
            item.get("explanation") or item.get("description") or title
        ).strip() or title
        completed.append(
            {
                "requirement_id": requirement_id,
                "title": title,
                "explanation": explanation,
                "criticality": str(item.get("criticality") or "MEDIUM").strip() or "MEDIUM",
                "check_script": stem,
                "match_pattern": _safe_match_pattern(
                    requirement_id,
                    str(item.get("match_pattern") or item.get("regex") or ""),
                ),
            }
        )
    return completed


def _stub_script(script_name: str, rules: list[dict[str, str]]) -> str:
    lines = [f"{rule['requirement_id']}=FAIL" for rule in rules]
    if script_name.endswith(".ps1"):
        return "\n".join(f"Write-Output '{line}'" for line in lines) + "\n"
    if script_name.endswith(".py"):
        return "\n".join(f"print('{line}')" for line in lines) + "\n"
    return "#!/bin/sh\n" + "\n".join(f"echo {line}" for line in lines) + "\n"


def _importable_script_name(script_name: str) -> str:
    """Rename a script the catalog would skip, such as a name containing _dev."""
    from secaudit_core.profile_packages import EXCLUDED_SCRIPT_MARKERS, REMEDIATION_SCRIPT_MARKER

    suffix = "sh"
    if script_name.endswith(".ps1"):
        suffix = "ps1"
    elif script_name.endswith(".py"):
        suffix = "py"
    lowered = script_name.lower()
    blocked = (*EXCLUDED_SCRIPT_MARKERS, REMEDIATION_SCRIPT_MARKER)
    if any(marker in lowered for marker in blocked):
        return f"check.{suffix}"
    return script_name


def _inline_target(value: Any) -> dict[str, Any] | None:
    """Turn an os or software value into an object. A plain name is not a file."""
    if isinstance(value, dict):
        block = dict(value)
        block["name"] = str(block.get("name") or "Custom").strip() or "Custom"
        block["vendor"] = str(block.get("vendor") or "Custom").strip() or "Custom"
        block["version"] = str(block.get("version") or "1").strip() or "1"
        return block
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.lower().endswith(".json"):
        text = text[:-5].strip()
    if not text:
        return None
    name, version = text, "1"
    head, _, tail = text.rpartition(" ")
    if head and any(character.isdigit() for character in tail):
        name, version = head.strip(), tail.strip()
    return {"name": name or "Custom", "vendor": "Custom", "version": version or "1"}


def normalize_package_files(files: Mapping[str, Any], *, profile_name: str = "") -> dict[str, Any]:
    """Fill the three files a custom profile import requires."""
    description = dict(files.get("description") if isinstance(files.get("description"), dict) else {})
    name = (profile_name or "").strip() or str(
        description.get("profile_name") or description.get("tech_name") or ""
    ).strip()
    description["profile_name"] = name
    description["profile_family"] = "custom"
    description["benchmark_ref"] = ""
    description["source_format"] = "custom"
    description["profile_rules"] = "profile_rules.json"
    description["encoding"] = description.get("encoding") or "utf-8"
    description["version"] = str(description.get("version") or "1.0")
    os_block = _inline_target(description.get("os"))
    software_block = _inline_target(description.get("software"))
    if os_block:
        description["os"] = os_block
    else:
        description.pop("os", None)
    if software_block:
        description["software"] = software_block
    else:
        description.pop("software", None)
    if "os" not in description and "software" not in description:
        description["os"] = {"name": "Custom", "vendor": "Custom", "version": "1"}

    script_name = str(files.get("script_name") or "check.sh").replace("\\", "/").split("/")[-1]
    if script_name in {"", ".", ".."} or not script_name.endswith((".sh", ".ps1", ".py")):
        script_name = "check.sh"
    script_name = _importable_script_name(script_name)
    stem = script_name.rsplit(".", 1)[0]
    rules_payload = files.get("rules")
    raw_rules: list[Any] = []
    if isinstance(rules_payload, dict) and isinstance(rules_payload.get("rules"), list):
        raw_rules = rules_payload["rules"]
    elif isinstance(rules_payload, list):
        raw_rules = rules_payload
    rules = _completed_rules(raw_rules, stem)
    script = files.get("script") if isinstance(files.get("script"), str) else ""
    if not rules and script.strip():
        found = list(dict.fromkeys(re.findall(r"RULE\d+", script)))
        rules = _completed_rules(
            [{"requirement_id": item, "title": item} for item in found],
            stem,
        )
    if rules and not script.strip():
        script = _stub_script(script_name, rules)
    return {
        "description": description,
        "rules": {"version": 1, "format": "secaudit.profile_rules", "rules": rules},
        "script_name": script_name,
        "script": script,
    }


_STUB_LINE = re.compile(
    r"^(?:#!/bin/sh|echo RULE\d+=FAIL|print\('RULE\d+=FAIL'\)|Write-Output 'RULE\d+=FAIL')$"
)


def _is_stub_script(script: str) -> bool:
    lines = [line.strip() for line in (script or "").splitlines() if line.strip()]
    return bool(lines) and all(_STUB_LINE.fullmatch(line) for line in lines)


def apply_operator_profile(files: Mapping[str, Any], spec: Mapping[str, Any]) -> dict[str, Any]:
    """Stamp only the fields the operator filled. Empty fields stay as the model wrote them."""
    description = dict(files.get("description") if isinstance(files.get("description"), dict) else {})
    version = str(spec.get("version") or "").strip()
    if version:
        description["version"] = version[:32]
    kind = spec.get("target_kind") if spec.get("target_kind") in {"os", "software"} else ""
    name = str(spec.get("name") or "").strip()
    vendor = str(spec.get("vendor") or "").strip()
    target_version = str(spec.get("target_version") or "").strip()
    if kind:
        description.pop("software" if kind == "os" else "os", None)
    if kind or name or vendor or target_version:
        chosen = kind or (
            "software"
            if isinstance(description.get("software"), dict) and not isinstance(description.get("os"), dict)
            else "os"
        )
        current = dict(description.get(chosen) or {}) if isinstance(description.get(chosen), dict) else {}
        if name:
            current["name"] = name[:128]
        if vendor:
            current["vendor"] = vendor[:128]
        if target_version:
            current["version"] = target_version[:64]
        current.setdefault("name", "Custom")
        current.setdefault("vendor", "Custom")
        current.setdefault("version", "1")
        description[chosen] = current
    overview = str(spec.get("overview") or "").strip()
    if overview:
        description["overview"] = overview[:500]
    purpose = str(spec.get("purpose") or "").strip()
    if purpose:
        description["purpose"] = purpose[:2000]
    rules = dict(files.get("rules") if isinstance(files.get("rules"), dict) else {})
    rule_rows = [dict(item) for item in rules.get("rules") or [] if isinstance(item, dict)]
    script = files.get("script") if isinstance(files.get("script"), str) else ""
    script_name = str(files.get("script_name") or "check.sh")
    script_kind = spec.get("script_kind") if spec.get("script_kind") in {"sh", "ps1", "py"} else ""
    if script_kind:
        script_name = f"check.{script_kind}"
        for rule in rule_rows:
            rule["check_script"] = "check"
        if not script.strip() or _is_stub_script(script):
            script = _stub_script(script_name, rule_rows)
    rules["rules"] = rule_rows
    return {
        "description": description,
        "rules": rules,
        "script_name": script_name,
        "script": script,
    }


def package_request_errors(files: Mapping[str, Any]) -> list[str]:
    """Reasons a generate request cannot become a profile. Empty means the files are usable."""
    description = files.get("description") if isinstance(files.get("description"), dict) else {}
    name = str(description.get("profile_name") or "").strip()
    errors: list[str] = []
    if not name:
        errors.append("Profile name is required")
    elif official_benchmark_name(name):
        errors.append("Package cannot be signed as CIS, STIG, or FSTEK")
    rules_payload = files.get("rules") if isinstance(files.get("rules"), dict) else {}
    rules = rules_payload.get("rules") if isinstance(rules_payload.get("rules"), list) else []
    if not rules:
        errors.append("This request did not describe any checks")
    return errors


def generated_package_files(raw: str, *, profile_name: str = "") -> dict[str, Any]:
    payload = _json_object(raw)
    description = payload.get("description") if isinstance(payload.get("description"), dict) else {}
    raw_rules = payload.get("rules")
    rules = raw_rules if isinstance(raw_rules, dict) else {"rules": raw_rules} if isinstance(raw_rules, list) else {}
    description = dict(description)
    description["profile_family"] = "custom"
    description["benchmark_ref"] = ""
    description["source_format"] = "custom"
    description.setdefault("profile_rules", "profile_rules.json")
    description.setdefault("encoding", "utf-8")
    script_name = str(payload.get("script_name") or "check.sh").replace("\\", "/").split("/")[-1]
    if not script_name.endswith((".sh", ".ps1", ".py")):
        script_name = f"{script_name}.sh"
    script = payload.get("script") if isinstance(payload.get("script"), str) else ""
    if isinstance(payload.get("error"), str) and not rules:
        description["error"] = payload["error"][:300]
    normalized = normalize_package_files(
        {
            "description": description,
            "rules": rules,
            "script_name": script_name,
            "script": script,
        },
        profile_name=profile_name,
    )
    normalized["description"].pop("error", None)
    return normalized


def write_generated_package(files: Mapping[str, Any], directory: Path) -> list[str]:
    """Write the three package files and run the same check as import."""
    from secaudit_core.profile_packages import validate_profile_package

    directory.mkdir(parents=True, exist_ok=True)
    description = dict(files.get("description") if isinstance(files.get("description"), dict) else {})
    description["profile_family"] = "custom"
    description["benchmark_ref"] = ""
    description["source_format"] = "custom"
    description.setdefault("profile_rules", "profile_rules.json")
    description.setdefault("encoding", "utf-8")
    rules = files.get("rules") if isinstance(files.get("rules"), dict) else {}
    script_name = str(files.get("script_name") or "check.sh").replace("\\", "/").split("/")[-1]
    if script_name in {"", ".", ".."} or not script_name.endswith((".sh", ".ps1", ".py")):
        script_name = "check.sh"
    script = files.get("script") if isinstance(files.get("script"), str) else ""
    errors: list[str] = []
    name = str(description.get("profile_name") or description.get("tech_name") or "")
    if official_benchmark_name(name):
        errors.append("Package cannot be signed as CIS, STIG, or FSTEK")
    (directory / "description.json").write_text(
        json.dumps(description, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (directory / "profile_rules.json").write_text(
        json.dumps(rules, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (directory / script_name).write_text(script, encoding="utf-8")
    try:
        validate_profile_package(directory)
    except Exception as exc:
        errors.append(str(exc))
    return errors
