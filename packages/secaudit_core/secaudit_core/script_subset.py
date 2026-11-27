"""Assemble audit/remediation scripts that only invoke selected RULE units.

Helpers/bootstrap stay intact. When no recognized markers exist, the original
script is returned unchanged (rely on SECAUDIT_RULES / SECAUDIT_REMEDIATE_RULES).
"""

from __future__ import annotations

import re
from pathlib import Path

from secaudit_core.profile_packages import rule_identity_keys

# Single-rule markers only. Do NOT match section ranges like "# RULE1-8" /
# "# RULE9-34" — those are headings inside multi-rule runners; treating them
# as unit boundaries chops functions mid-body (bash: unexpected EOF).
_RULE_COMMENT = re.compile(
    r"^[ \t]*#[ \t]*(?:SECAUDIT_RULE_BEGIN[ \t]+)?RULE0*(\d+)\b(?![ \t]*-\d)[^\n]*$",
    re.IGNORECASE | re.MULTILINE,
)
_RULE_COMMENT_END = re.compile(
    r"^[ \t]*#[ \t]*SECAUDIT_RULE_END[ \t]+RULE0*(\d+)\b[^\n]*$",
    re.IGNORECASE | re.MULTILINE,
)
_RULE_END_CALL = re.compile(
    r"sec_audit_rule_end[ \t]+(\d+)\b",
    re.IGNORECASE,
)
_PS_RULE_COMMENT = re.compile(
    r"^[ \t]*#[ \t]*(?:SECAUDIT_RULE_BEGIN[ \t]+)?(RULE\d+)\b(?![ \t]*-\d)[^\n]*$",
    re.IGNORECASE | re.MULTILINE,
)
_MAIN_BASH = re.compile(
    r"(?P<head>^[ \t]*(?:function[ \t]+)?(?:sec_audit_main|secaudit_main)[ \t]*\(\)[ \t]*\{[ \t]*\n)"
    r"(?P<body>.*?)"
    r"(?P<tail>^[ \t]*\})",
    re.IGNORECASE | re.MULTILINE | re.DOTALL,
)
_HELPER_MARK = "secaudit_rule_enabled"

_BASH_HELPER = r'''
# --- SecAudit rule allowlist (SECAUDIT_RULES / SECAUDIT_REMEDIATE_RULES) ---
secaudit_rule_enabled() {
    local raw="${SECAUDIT_RULES:-${SECAUDIT_REMEDIATE_RULES:-}}" id="$1" token n want
    [ -z "$raw" ] && return 0
    n="${id#RULE}"; n="${n#rule}"; n="${n#Rule}"
    case "$n" in (*[!0-9]*|"") want=$(printf '%s' "$id" | tr '[:lower:]' '[:upper:]') ;;
        *) want="RULE$((10#$n))" ;;
    esac
    local IFS=','
    for token in $raw; do
        token=$(printf '%s' "$token" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')
        [ -z "$token" ] && continue
        local tn="${token#RULE}"
        case "$tn" in (*[!0-9]*|"") ;;
            *) token="RULE$((10#$tn))" ;;
        esac
        [ "$token" = "$want" ] && return 0
    done
    return 1
}
'''

_PS_HELPER = r'''
# --- SecAudit rule allowlist (SECAUDIT_RULES / SECAUDIT_REMEDIATE_RULES) ---
function Test-SecAuditRuleEnabled {
    param([Parameter(Mandatory=$true)][string]$Id)
    $raw = $env:SECAUDIT_RULES
    if ([string]::IsNullOrWhiteSpace($raw)) { $raw = $env:SECAUDIT_REMEDIATE_RULES }
    if ([string]::IsNullOrWhiteSpace($raw)) { return $true }
    $want = $Id.Trim().ToUpperInvariant()
    if ($want -match '^RULE0*(\d+)$') { $want = "RULE$([int]$Matches[1])" }
    foreach ($token in ($raw -split ',')) {
        $t = $token.Trim().ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        if ($t -match '^RULE0*(\d+)$') { $t = "RULE$([int]$Matches[1])" }
        if ($t -eq $want) { return $true }
    }
    return $false
}
'''

_PY_HELPER = '''
# --- SecAudit rule allowlist (SECAUDIT_RULES / SECAUDIT_REMEDIATE_RULES) ---
def secaudit_rule_enabled(rule_id) -> bool:
    import os, re
    raw = (os.environ.get("SECAUDIT_RULES") or os.environ.get("SECAUDIT_REMEDIATE_RULES") or "").strip()
    if not raw:
        return True
    text = str(rule_id).strip().upper()
    m = re.fullmatch(r"RULE0*(\\d+)", text)
    if m:
        text = f"RULE{int(m.group(1))}"
    elif text.isdigit():
        text = f"RULE{int(text)}"
    for token in raw.split(","):
        t = token.strip().upper()
        if not t:
            continue
        tm = re.fullmatch(r"RULE0*(\\d+)", t)
        if tm:
            t = f"RULE{int(tm.group(1))}"
        if t == text:
            return True
    return False
'''


def normalize_allowed_ids(allowed: set[str] | list[str] | None) -> set[str] | None:
    """None = run all. Empty set/list = run nothing (explicit empty selection)."""
    if allowed is None:
        return None
    keys: set[str] = set()
    for item in allowed:
        for key in rule_identity_keys(str(item)):
            keys.add(key)
            m = re.fullmatch(r"RULE0*(\d+)", key, flags=re.IGNORECASE)
            if m:
                keys.add(str(int(m.group(1))))
    return keys


def _id_allowed(num_or_id: str, allowed: set[str]) -> bool:
    for key in rule_identity_keys(num_or_id if num_or_id.upper().startswith("RULE") else f"RULE{num_or_id}"):
        if key in allowed:
            return True
        if key.isdigit() and key in allowed:
            return True
    bare = re.sub(r"^RULE0*", "", num_or_id, flags=re.IGNORECASE)
    return bare in allowed or f"RULE{bare}" in allowed or f"RULE{int(bare)}" in allowed if bare.isdigit() else False


def _ensure_bash_helper(text: str) -> str:
    if _HELPER_MARK in text:
        return text
    # After shebang / bash bootstrap block if present
    lines = text.splitlines(keepends=True)
    insert_at = 0
    if lines and lines[0].startswith("#!"):
        insert_at = 1
    helper = _BASH_HELPER.lstrip("\n")
    if not helper.endswith("\n"):
        helper += "\n"
    return "".join(lines[:insert_at]) + "\n" + helper + "".join(lines[insert_at:])


def _ensure_ps_helper(text: str) -> str:
    if "Test-SecAuditRuleEnabled" in text:
        return text
    return _PS_HELPER.lstrip("\n") + "\n" + text


def _ensure_py_helper(text: str) -> str:
    if "def secaudit_rule_enabled" in text:
        return text
    lines = text.splitlines(keepends=True)
    i = 0
    if lines and lines[0].startswith("#!"):
        i = 1
    # Skip one module docstring.
    if i < len(lines):
        stripped = lines[i].lstrip()
        for q in ('"""', "'''"):
            if stripped.startswith(q):
                if stripped.count(q) >= 2 and len(stripped.strip()) > len(q) * 2:
                    i += 1
                else:
                    i += 1
                    while i < len(lines) and q not in lines[i]:
                        i += 1
                    if i < len(lines):
                        i += 1
                break
    # Skip blank lines and from __future__ imports so the helper never precedes them.
    while i < len(lines):
        s = lines[i].strip()
        if s == "" or s.startswith("from __future__"):
            i += 1
            continue
        break
    helper = _PY_HELPER.lstrip("\n")
    if not helper.endswith("\n"):
        helper += "\n"
    return "".join(lines[:i]) + "\n" + helper + "".join(lines[i:])


def _shell_braces_balanced(text: str) -> bool:
    """Cheap structural guard: comment-trim must not leave unclosed { ... }."""
    depth = 0
    for raw in text.splitlines():
        line = raw.lstrip()
        if not line or line.startswith("#"):
            continue
        # Ignore typical single-quoted chunks (opts / awk); good enough for gate.
        cleaned = re.sub(r"'[^']*'", "''", raw)
        cleaned = re.sub(r'"[^"]*"', '""', cleaned)
        depth += cleaned.count("{") - cleaned.count("}")
        if depth < 0:
            return False
    return depth == 0


def _subset_bash_rule_comment_blocks(text: str, allowed: set[str]) -> str | None:
    # Bare "# RULEN" headings inside section runners are not safe unit boundaries:
    # trimming them yields brace-balanced scripts that no longer call main/runners.
    # Only explicit BEGIN/END markers opt into comment-block assembly.
    if "SECAUDIT_RULE_BEGIN" not in text.upper() and not _RULE_COMMENT_END.search(text):
        return None
    matches = list(_RULE_COMMENT.finditer(text))
    if len(matches) < 2 and not (matches and _RULE_COMMENT_END.search(text)):
        if not matches:
            return None
    # Walk blocks from each RULE comment to the next (or explicit END / EOF-ish)
    out: list[str] = []
    last = 0
    kept_any = False
    for i, match in enumerate(matches):
        out.append(text[last:match.start()])
        num = match.group(1)
        # end at next RULE comment, SECAUDIT_RULE_END for same id, or next top-level function/main
        if i + 1 < len(matches):
            end = matches[i + 1].start()
        else:
            end = len(text)
        block = text[match.start():end]
        end_m = _RULE_COMMENT_END.search(block)
        if end_m and end_m.group(1).lstrip("0") == num.lstrip("0"):
            # keep through END line
            pass
        if _id_allowed(num, allowed):
            out.append(block)
            kept_any = True
        else:
            # drop unit body; keep a short marker so line numbers stay debuggable
            out.append(f"# SECAUDIT_RULE_SKIPPED RULE{int(num)}\n")
        last = end
    out.append(text[last:])
    if not kept_any and matches:
        # no-op script that still exits cleanly
        return _ensure_bash_helper(
            "#!/bin/bash\nsecaudit_rule_enabled() { return 1; }\n"
            "printf '%s\\n' '[secaudit] no selected rules matched script units'\nexit 0\n"
        )
    assembled = "".join(out)
    # Markers often sit inside section runners; dropping tails chops closing braces.
    # Fall back to env-allowlist-only (caller keeps full script) when structure breaks.
    if not _shell_braces_balanced(assembled):
        return None
    return assembled


def _subset_bash_main_rule_end(text: str, allowed: set[str]) -> str | None:
    match = _MAIN_BASH.search(text)
    if not match or not _RULE_END_CALL.search(match.group("body")):
        return None
    body = match.group("body")
    # Split into statement groups ending with sec_audit_rule_end N
    parts: list[str] = []
    buf: list[str] = []
    kept = 0
    for line in body.splitlines(keepends=True):
        buf.append(line)
        end = _RULE_END_CALL.search(line)
        if end:
            chunk = "".join(buf)
            if _id_allowed(end.group(1), allowed):
                parts.append(chunk)
                kept += 1
            buf = []
    # trailing non-rule lines (e.g. blank before closing)
    trailing = "".join(buf)
    new_body = "".join(parts) + trailing
    if kept == 0:
        new_body = '    printf "%s\\n" "[secaudit] no selected rules matched script units"\n'
    rebuilt = text[: match.start("body")] + new_body + text[match.end("body") :]
    return rebuilt


def _subset_ps_rule_blocks(text: str, allowed: set[str]) -> str | None:
    if "SECAUDIT_RULE_BEGIN" not in text.upper():
        return None
    matches = list(_PS_RULE_COMMENT.finditer(text))
    if not matches:
        return None
    out: list[str] = []
    last = 0
    kept = 0
    for i, match in enumerate(matches):
        out.append(text[last:match.start()])
        rid = match.group(1)
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[match.start():end]
        if _id_allowed(rid, allowed):
            out.append(block)
            kept += 1
        else:
            out.append(f"# SECAUDIT_RULE_SKIPPED {rid}\n")
        last = end
    out.append(text[last:])
    if kept == 0:
        return (
            _PS_HELPER.lstrip("\n")
            + "\nWrite-Output '[secaudit] no selected rules matched script units'\nexit 0\n"
        )
    assembled = "".join(out)
    if not _shell_braces_balanced(assembled):
        return None
    return assembled


def _subset_py_main_calls(text: str, allowed: set[str]) -> str | None:
    """Keep secaudit_check_N / secaudit_remediate_N calls only when selected."""
    call_re = re.compile(
        r"^([ \t]*)((?:secaudit_check_|secaudit_remediate_|sec_audit_rule_)(\d+)\s*\(.*)$",
        re.MULTILINE,
    )
    if not call_re.search(text):
        return None

    def repl(m: re.Match[str]) -> str:
        indent, call, num = m.group(1), m.group(2), m.group(3)
        if _id_allowed(num, allowed):
            return m.group(0)
        return f"{indent}pass  # SECAUDIT_RULE_SKIPPED RULE{int(num)}: {call}"

    return call_re.sub(repl, text)


def subset_script(
    text: str,
    allowed: set[str] | list[str] | None,
    *,
    path: str | Path | None = None,
    kind: str = "audit",
) -> str:
    """Return script text limited to selected rules, or original when allowlist is open."""
    del kind  # reserved for future remediation-specific hints
    normalized = normalize_allowed_ids(allowed)
    if normalized is None:
        return text

    suffix = Path(path).suffix.lower() if path else ""
    name = Path(path).name.lower() if path else ""

    if suffix == ".ps1" or name.endswith(".ps1"):
        text = _ensure_ps_helper(text)
        subset = _subset_ps_rule_blocks(text, normalized)
        return subset if subset is not None else text

    if suffix == ".py" or name.endswith(".py"):
        text = _ensure_py_helper(text)
        subset = _subset_py_main_calls(text, normalized)
        return subset if subset is not None else text

    # shell / unknown → bash strategies
    text = _ensure_bash_helper(text)
    for strategy in (_subset_bash_main_rule_end, _subset_bash_rule_comment_blocks):
        subset = strategy(text, normalized)
        if subset is not None:
            return _ensure_bash_helper(subset)
    return text


def materialize_subset_script(
    script_path: Path,
    allowed: set[str] | list[str] | None,
    *,
    kind: str = "audit",
) -> Path:
    """Write a temp subset script when allowlist is set; otherwise return original path."""
    import tempfile

    normalized = normalize_allowed_ids(allowed)
    if normalized is None:
        return script_path
    original = script_path.read_text(encoding="utf-8", errors="replace")
    assembled = subset_script(original, normalized, path=script_path, kind=kind)
    if assembled == original:
        return script_path
    suffix = script_path.suffix or ".sh"
    tmp = tempfile.NamedTemporaryFile(
        delete=False, suffix=suffix, prefix=f"secaudit_subset_{script_path.stem}_"
    )
    tmp.write(assembled.encode("utf-8"))
    tmp.close()
    return Path(tmp.name)
