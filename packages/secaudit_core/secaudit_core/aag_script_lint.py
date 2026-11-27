"""Static checks for AAG-generated check scripts before a draft is kept."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def lint_generated_script(script_name: str, script: str) -> list[str]:
    """Return human-readable lint errors. Empty means the script is acceptable."""
    text = script if isinstance(script, str) else ""
    if not text.strip():
        return ["Check script is empty"]
    name = (script_name or "check.sh").replace("\\", "/").split("/")[-1].lower()
    if name.endswith(".py"):
        return _lint_python(text)
    if name.endswith(".ps1"):
        return _lint_powershell(text)
    return _lint_shell(text)


def _lint_python(script: str) -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "check.py"
        path.write_text(script if script.endswith("\n") else script + "\n", encoding="utf-8")
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "py_compile", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ["Python syntax: py_compile timed out"]
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "invalid syntax").strip()[:300]
            return [f"Python syntax: {detail}"]
    return []


def script_contract_errors(script: str, rule_ids: list[str]) -> list[str]:
    """Each rule must be able to print RULE=PASS or RULE=FAIL. The script is not run."""
    errors: list[str] = []
    for rule_id in rule_ids:
        if not rule_id or _rule_prints_result(script, rule_id):
            continue
        errors.append(f"{rule_id} does not print PASS or FAIL")
    return errors


def _rule_prints_result(script: str, rule_id: str) -> bool:
    escaped = re.escape(rule_id)
    if re.search(rf"{escaped}\s*=\s*(?:PASS|FAIL)\b", script, re.IGNORECASE):
        return True
    # shortcut: a quoted rule id plus a quoted PASS/FAIL anywhere, including JSONL.
    quoted_rule = re.search(rf"['\"]{escaped}['\"]", script)
    quoted_status = re.search(r"['\"](?:PASS|FAIL)['\"]", script, re.IGNORECASE)
    return bool(quoted_rule and quoted_status)


def _lint_shell(script: str) -> list[str]:
    with tempfile.NamedTemporaryFile("w", suffix=".sh", encoding="utf-8", delete=False) as handle:
        handle.write(script if script.endswith("\n") else script + "\n")
        path = handle.name
    try:
        shellcheck = shutil.which("shellcheck")
        if shellcheck:
            proc = subprocess.run(
                [shellcheck, "-e", "SC2148", "-f", "gcc", path],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            findings = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
            if findings:
                return [f"shellcheck: {line}" for line in findings[:8]]
            if proc.returncode not in (0, 1) and (proc.stderr or "").strip():
                return [f"shellcheck: {(proc.stderr or '').strip()[:300]}"]
            return []
        bash = shutil.which("bash")
        if bash:
            proc = subprocess.run(
                [bash, "-n", path],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if proc.returncode != 0:
                detail = (proc.stderr or proc.stdout or "syntax error").strip()[:300]
                return [f"bash -n: {detail}"]
            return []
        return _heuristic_shell(script)
    except subprocess.TimeoutExpired:
        return ["Shell lint timed out"]
    finally:
        Path(path).unlink(missing_ok=True)


def _lint_powershell(script: str) -> list[str]:
    for exe in ("pwsh", "powershell"):
        if not shutil.which(exe):
            continue
        with tempfile.NamedTemporaryFile("w", suffix=".ps1", encoding="utf-8", delete=False) as handle:
            handle.write(script if script.endswith("\n") else script + "\n")
            path = handle.name
        try:
            # ParseInput fills [ref]$errors without executing the script.
            safe_path = path.replace("'", "''")
            command = (
                "$e=$null; $t=$null; "
                f"$null=[System.Management.Automation.Language.Parser]::ParseFile('{safe_path}', [ref]$t, [ref]$e); "
                "if($e){$e|ForEach-Object{$_.ToString()}}"
            )
            proc = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            findings = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
            if findings:
                return [f"PowerShell AST: {line}" for line in findings[:8]]
            if proc.returncode != 0 and (proc.stderr or "").strip():
                return [f"PowerShell AST: {(proc.stderr or '').strip()[:300]}"]
            return []
        except subprocess.TimeoutExpired:
            return ["PowerShell lint timed out"]
        finally:
            Path(path).unlink(missing_ok=True)
    return _heuristic_powershell(script)


def _heuristic_shell(script: str) -> list[str]:
    errors: list[str] = []
    if script.count("'") % 2:
        errors.append("Shell script has unmatched single quotes")
    if script.count('"') % 2:
        errors.append("Shell script has unmatched double quotes")
    opens = script.count("if ") + script.count("if\t") + script.count("\nif")
    # Cheap brace/fi balance for POSIX shells.
    if script.count("{{") == 0 and script.count("{") != script.count("}"):
        errors.append("Shell script has unmatched braces")
    if "if " in script or "\nif" in script:
        if script.count("\nfi") + (1 if script.strip().endswith("fi") else 0) < 1 and "fi" not in script:
            if opens:
                errors.append("Shell script may be missing fi")
    return errors


def _heuristic_powershell(script: str) -> list[str]:
    errors: list[str] = []
    if script.count("'") % 2:
        errors.append("PowerShell script has unmatched single quotes")
    if script.count('"') % 2:
        errors.append("PowerShell script has unmatched double quotes")
    if script.count("{") != script.count("}"):
        errors.append("PowerShell script has unmatched braces")
    return errors
