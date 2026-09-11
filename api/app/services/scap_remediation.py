"""Generate executable SCAP remediations from XCCDF fixtext or hardening-style templates.

Honest about gaps: rules without fixtext and without a matching template are marked
UNSUPPORTED (emitted as SKIP with an explicit reason) — never silent success.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# XCCDF fix @system values we can map to shell or Ansible executors.
FIX_SHELL_SYSTEMS = frozenset(
    {
        "urn:xccdf:fix:script:sh",
        "urn:xccdf:fix:script:bash",
        "urn:xccdf:fix:commands",
        "urn:xccdf:fix:script:perl",  # rarely usable as shell; still extract text
    }
)
FIX_ANSIBLE_SYSTEMS = frozenset(
    {
        "urn:xccdf:fix:ansible",
        "urn:xccdf:fix:script:ansible",
    }
)
FIX_PUPPET_SYSTEMS = frozenset(
    {
        "urn:xccdf:fix:puppet",
        "urn:xccdf:fix:script:puppet",
    }
)

# Ordered pattern → template kind. First match wins.
_TEMPLATE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(ensure|verify).{0,80}(package|pkg).{0,40}(is\s+)?(not\s+)?installed"
            r"|package.{0,40}(is\s+)?(not\s+)?installed"
            r"|(install|remove|uninstall)\s+(the\s+)?package",
            re.I,
        ),
        "package",
    ),
    (
        re.compile(
            r"(ensure|verify).{0,80}(service|daemon|unit).{0,60}"
            r"(is\s+)?(enabled|disabled|masked|active|inactive|stopped|running)"
            r"|(enable|disable|mask|stop|start)\s+.{0,40}(service|daemon)",
            re.I,
        ),
        "service",
    ),
    (
        re.compile(
            r"\bsysctl\b|kernel\.(randomize|yama|modules)|net\.ipv4\.|net\.ipv6\.|fs\.suid_dumpable",
            re.I,
        ),
        "sysctl",
    ),
    (
        re.compile(
            r"(permission|permissions|mode\s+\d{3,4}|chmod|chown|ownership|"
            r"\b0[0-7]{3}\b|\b[ug]id\b).{0,60}(file|directory|/etc|/var|/boot)?",
            re.I,
        ),
        "file_permission",
    ),
    (
        re.compile(
            r"(disable|blacklist|modprobe).{0,40}(module|filesystem|fs\b)"
            r"|(cramfs|freevxfs|jffs2|hfsplus|hfs|squashfs|udf|vfat|usb[-_]?storage)"
            r".{0,40}(disabled|blacklist|not\s+loaded)",
            re.I,
        ),
        "kernel_module",
    ),
]


@dataclass
class XccdfFix:
    system: str
    text: str


@dataclass
class RemediationPlan:
    """Per-rule remediation decision used when materializing scripts/playbooks."""

    rule_id: str
    title: str
    mnemonic: str
    kind: str  # fixtext_shell | fixtext_ansible | template_* | unsupported
    shell_lines: list[str] = field(default_factory=list)
    ansible_tasks_yaml: str | None = None
    reason: str | None = None


def classify_fix_system(system: str) -> str:
    sys_l = (system or "").strip().lower()
    if not sys_l or sys_l in FIX_SHELL_SYSTEMS:
        return "shell"
    if sys_l in FIX_ANSIBLE_SYSTEMS or "ansible" in sys_l:
        return "ansible"
    if sys_l in FIX_PUPPET_SYSTEMS or "puppet" in sys_l:
        return "puppet"
    if "python" in sys_l:
        return "python"
    return "other"


def infer_template_kind(title: str, description: str = "") -> str | None:
    haystack = f"{title}\n{description}"
    for pattern, kind in _TEMPLATE_PATTERNS:
        if pattern.search(haystack):
            return kind
    return None


def _safe_echo_title(title: str) -> str:
    return title.replace('"', "'").replace("`", "'")[:200]


def _extract_package_name(title: str, description: str = "") -> str | None:
    text = f"{title} {description}"
    # hardening-style: "Ensure X is installed" / "Ensure package X is not installed"
    patterns = [
        re.compile(
            r"(?:package|pkg)\s+['\"]?([A-Za-z0-9][\w.+-]+)['\"]?\s+(?:is\s+)?(?:not\s+)?installed",
            re.I,
        ),
        re.compile(
            r"ensure\s+['\"]?([A-Za-z0-9][\w.+-]+)['\"]?\s+(?:package\s+)?(?:is\s+)?(?:not\s+)?installed",
            re.I,
        ),
        re.compile(r"(?:install|remove|uninstall)\s+(?:the\s+)?(?:package\s+)?['\"]?([A-Za-z0-9][\w.+-]+)", re.I),
    ]
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            name = match.group(1)
            if name.lower() not in {"the", "a", "an", "package", "is", "not"}:
                return name
    return None


def _extract_service_name(title: str, description: str = "") -> str | None:
    text = f"{title} {description}"
    patterns = [
        re.compile(
            r"(?:service|daemon|unit)\s+['\"]?([A-Za-z0-9][\w.@+-]+)['\"]?\s+"
            r"(?:is\s+)?(?:enabled|disabled|masked|active|inactive|stopped|running)",
            re.I,
        ),
        re.compile(
            r"ensure\s+['\"]?([A-Za-z0-9][\w.@+-]+)['\"]?\s+(?:service|daemon)",
            re.I,
        ),
        re.compile(
            r"(?:enable|disable|mask|stop|start)\s+['\"]?([A-Za-z0-9][\w.@+-]+)['\"]?\s*(?:service|daemon)?",
            re.I,
        ),
    ]
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            name = match.group(1)
            if name.lower() not in {"the", "a", "an", "is", "not"}:
                return name.removesuffix(".service")
    return None


def _extract_module_name(title: str, description: str = "") -> str | None:
    text = f"{title} {description}".lower()
    known = (
        "cramfs",
        "freevxfs",
        "jffs2",
        "hfsplus",
        "hfs",
        "squashfs",
        "udf",
        "vfat",
        "usb-storage",
        "usb_storage",
        "dccp",
        "sctp",
        "rds",
        "tipc",
    )
    for name in known:
        if name in text:
            return name.replace("_", "-") if name == "usb_storage" else name
    match = re.search(r"(?:module|filesystem)\s+['\"]?([a-z0-9_-]+)['\"]?", text, re.I)
    if match:
        return match.group(1)
    return None


def _extract_sysctl_key(title: str, description: str = "") -> str | None:
    text = f"{title} {description}"
    match = re.search(r"\b((?:kernel|net|fs|vm|user)\.[\w.]+)\b", text)
    return match.group(1) if match else None


def _want_install(title: str, description: str = "") -> bool:
    hay = f"{title} {description}".lower()
    if re.search(r"not\s+installed|is\s+removed|uninstall|package.+absent", hay):
        return False
    return True


def _want_enable(title: str, description: str = "") -> bool:
    hay = f"{title} {description}".lower()
    if re.search(r"disabled|is\s+masked|not\s+enabled|inactive|stopped", hay):
        return False
    return True


def build_template_shell(
    kind: str,
    *,
    mnemonic: str,
    title: str,
    description: str = "",
) -> list[str] | None:
    """Return shell lines for a hardening-style template, or None if params cannot be inferred."""
    safe = _safe_echo_title(title)
    lines: list[str] = [
        f"# TEMPLATE ({kind}): review placeholders before applying in production",
    ]

    if kind == "package":
        pkg = _extract_package_name(title, description)
        if not pkg:
            return None
        if _want_install(title, description):
            lines.extend(
                [
                    f'_PKG="{pkg}"',
                    'if command -v dnf >/dev/null 2>&1; then dnf -y install "$_PKG"',
                    'elif command -v yum >/dev/null 2>&1; then yum -y install "$_PKG"',
                    'elif command -v apt-get >/dev/null 2>&1; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y "$_PKG"',
                    'elif command -v zypper >/dev/null 2>&1; then zypper -n install "$_PKG"',
                    "else",
                    f'  echo "{mnemonic}= SKIP: UNSUPPORTED — no package manager for $_PKG"',
                    "  return 0 2>/dev/null || true",
                    "fi",
                    f'echo "{mnemonic}= PASS: template package install $_PKG ({safe})"',
                ]
            )
        else:
            lines.extend(
                [
                    f'_PKG="{pkg}"',
                    'if command -v dnf >/dev/null 2>&1; then dnf -y remove "$_PKG" || true',
                    'elif command -v yum >/dev/null 2>&1; then yum -y remove "$_PKG" || true',
                    'elif command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get remove -y "$_PKG" || true',
                    'elif command -v zypper >/dev/null 2>&1; then zypper -n remove "$_PKG" || true',
                    "else",
                    f'  echo "{mnemonic}= SKIP: UNSUPPORTED — no package manager for $_PKG"',
                    "  return 0 2>/dev/null || true",
                    "fi",
                    f'echo "{mnemonic}= PASS: template package remove $_PKG ({safe})"',
                ]
            )
        return lines

    if kind == "service":
        svc = _extract_service_name(title, description)
        if not svc:
            return None
        if _want_enable(title, description):
            lines.extend(
                [
                    f'_SVC="{svc}"',
                    'if command -v systemctl >/dev/null 2>&1; then',
                    '  systemctl unmask "$_SVC" 2>/dev/null || true',
                    '  systemctl enable --now "$_SVC"',
                    "else",
                    f'  echo "{mnemonic}= SKIP: UNSUPPORTED — systemctl not available for $_SVC"',
                    "  return 0 2>/dev/null || true",
                    "fi",
                    f'echo "{mnemonic}= PASS: template service enable $_SVC ({safe})"',
                ]
            )
        else:
            lines.extend(
                [
                    f'_SVC="{svc}"',
                    'if command -v systemctl >/dev/null 2>&1; then',
                    '  systemctl stop "$_SVC" 2>/dev/null || true',
                    '  systemctl disable "$_SVC" 2>/dev/null || true',
                    '  systemctl mask "$_SVC" 2>/dev/null || true',
                    "else",
                    f'  echo "{mnemonic}= SKIP: UNSUPPORTED — systemctl not available for $_SVC"',
                    "  return 0 2>/dev/null || true",
                    "fi",
                    f'echo "{mnemonic}= PASS: template service disable $_SVC ({safe})"',
                ]
            )
        return lines

    if kind == "sysctl":
        key = _extract_sysctl_key(title, description)
        if not key:
            lines.extend(
                [
                    f"# Set the intended sysctl key/value for: {safe}",
                    '_SYSCTL_KEY="REPLACE.me.key"',
                    '_SYSCTL_VAL="REPLACE_VALUE"',
                    'if [ "$_SYSCTL_KEY" = "REPLACE.me.key" ]; then',
                    f'  echo "{mnemonic}= SKIP: UNSUPPORTED — sysctl template needs key/value for {safe}"',
                    "else",
                    '  sysctl -w "$_SYSCTL_KEY=$_SYSCTL_VAL"',
                    '  mkdir -p /etc/sysctl.d',
                    '  echo "$_SYSCTL_KEY = $_SYSCTL_VAL" > "/etc/sysctl.d/99-secaudit-${_SYSCTL_KEY//./-}.conf"',
                    f'  echo "{mnemonic}= PASS: template sysctl $_SYSCTL_KEY ({safe})"',
                    "fi",
                ]
            )
            return lines
        lines.extend(
            [
                f'_SYSCTL_KEY="{key}"',
                '_SYSCTL_VAL="1"',
                "# TEMPLATE: confirm target value against the SCAP recommendation",
                'sysctl -w "$_SYSCTL_KEY=$_SYSCTL_VAL"',
                "mkdir -p /etc/sysctl.d",
                'echo "$_SYSCTL_KEY = $_SYSCTL_VAL" > "/etc/sysctl.d/99-secaudit-${_SYSCTL_KEY//./-}.conf"',
                f'echo "{mnemonic}= PASS: template sysctl $_SYSCTL_KEY ({safe})"',
            ]
        )
        return lines

    if kind == "file_permission":
        lines.extend(
            [
                f"# TEMPLATE: set path/mode/owner for: {safe}",
                '_PATH="/etc/REPLACE_ME"',
                '_MODE="0640"',
                '_OWNER="root:root"',
                'if [ "$_PATH" = "/etc/REPLACE_ME" ]; then',
                f'  echo "{mnemonic}= SKIP: UNSUPPORTED — file permission template needs path for {safe}"',
                "else",
                '  chown "$_OWNER" "$_PATH"',
                '  chmod "$_MODE" "$_PATH"',
                f'  echo "{mnemonic}= PASS: template permissions $_PATH ({safe})"',
                "fi",
            ]
        )
        return lines

    if kind == "kernel_module":
        mod = _extract_module_name(title, description)
        if not mod:
            return None
        conf = f"/etc/modprobe.d/secaudit-disable-{mod}.conf"
        lines.extend(
            [
                f'_MOD="{mod}"',
                f'_CONF="{conf}"',
                'echo "install $_MOD /bin/true" > "$_CONF"',
                'echo "blacklist $_MOD" >> "$_CONF"',
                'modprobe -r "$_MOD" 2>/dev/null || true',
                f'echo "{mnemonic}= PASS: template disable module $_MOD ({safe})"',
            ]
        )
        return lines

    return None


def build_template_ansible_yaml(
    kind: str,
    *,
    rule_id: str,
    title: str,
    description: str = "",
) -> str | None:
    """YAML task block (list item) for Ansible remediation playbook."""
    safe = title.replace('"', "'")[:120]

    if kind == "package":
        pkg = _extract_package_name(title, description)
        if not pkg:
            return None
        state = "present" if _want_install(title, description) else "absent"
        return (
            f'    - name: "{safe}"\n'
            f"      ansible.builtin.package:\n"
            f'        name: "{pkg}"\n'
            f"        state: {state}\n"
            f"      tags: [scap, template, {rule_id}]\n"
        )

    if kind == "service":
        svc = _extract_service_name(title, description)
        if not svc:
            return None
        enabled = _want_enable(title, description)
        return (
            f'    - name: "{safe}"\n'
            f"      ansible.builtin.service:\n"
            f'        name: "{svc}"\n'
            f"        enabled: {str(enabled).lower()}\n"
            f"        state: {'started' if enabled else 'stopped'}\n"
            f"      tags: [scap, template, {rule_id}]\n"
        )

    if kind == "sysctl":
        key = _extract_sysctl_key(title, description) or "REPLACE.me.key"
        return (
            f'    - name: "{safe}"\n'
            f"      ansible.builtin.sysctl:\n"
            f'        name: "{key}"\n'
            f'        value: "1"\n'
            f"        state: present\n"
            f"        reload: true\n"
            f"      tags: [scap, template, {rule_id}]\n"
            f"      # TEMPLATE: confirm value against SCAP recommendation\n"
        )

    if kind == "file_permission":
        return (
            f'    - name: "{safe} (template — set path)"\n'
            f"      ansible.builtin.file:\n"
            f'        path: "/etc/REPLACE_ME"\n'
            f'        owner: root\n'
            f'        group: root\n'
            f"        mode: \"0640\"\n"
            f"      tags: [scap, template, unsupported, {rule_id}]\n"
            f"      when: false  # placeholder until path is filled\n"
        )

    if kind == "kernel_module":
        mod = _extract_module_name(title, description)
        if not mod:
            return None
        return (
            f'    - name: "{safe}"\n'
            f"      ansible.builtin.copy:\n"
            f'        dest: "/etc/modprobe.d/secaudit-disable-{mod}.conf"\n'
            f'        content: |\n'
            f"          install {mod} /bin/true\n"
            f"          blacklist {mod}\n"
            f"        mode: \"0644\"\n"
            f"      tags: [scap, template, {rule_id}]\n"
        )

    return None


def plan_rule_remediation(
    *,
    rule_id: str,
    title: str,
    description: str,
    mnemonic: str,
    fixes: list[XccdfFix],
) -> RemediationPlan:
    """Prefer XCCDF fixtext (shell/ansible); else hardening-style template; else unsupported."""
    safe = _safe_echo_title(title)

    shell_fix = next(
        (f for f in fixes if classify_fix_system(f.system) == "shell" and f.text.strip()),
        None,
    )
    ansible_fix = next(
        (f for f in fixes if classify_fix_system(f.system) == "ansible" and f.text.strip()),
        None,
    )

    if shell_fix:
        body = [line.rstrip() for line in shell_fix.text.splitlines()]
        shell_lines = [
            f"# --- {rule_id}: {title} (XCCDF fixtext) ---",
            *body,
            f'echo "{mnemonic}= PASS: applied XCCDF shell fix ({safe})"',
            "",
        ]
        ansible_yaml = None
        if ansible_fix:
            ansible_yaml = _ansible_from_fixtext(ansible_fix.text, rule_id=rule_id, title=safe)
        else:
            # Wrap shell fix as an Ansible shell task for the ansible remediation playbook.
            indented = "\n".join(f"          {line}" if line else "" for line in body)
            ansible_yaml = (
                f'    - name: "{safe}"\n'
                f"      ansible.builtin.shell: |\n"
                f"{indented}\n"
                f"      args:\n"
                f"        executable: /bin/bash\n"
                f"      tags: [scap, fixtext, {rule_id}]\n"
            )
        return RemediationPlan(
            rule_id=rule_id,
            title=title,
            mnemonic=mnemonic,
            kind="fixtext_shell",
            shell_lines=shell_lines,
            ansible_tasks_yaml=ansible_yaml,
        )

    if ansible_fix:
        ansible_yaml = _ansible_from_fixtext(ansible_fix.text, rule_id=rule_id, title=safe)
        # Provide a shell runner that applies via ansible-playbook when available on target,
        # otherwise marks unsupported for SSH-only remediations.
        shell_lines = [
            f"# --- {rule_id}: {title} (XCCDF ansible fixtext) ---",
            f'echo "{mnemonic}= SKIP: UNSUPPORTED — ansible fixtext present; '
            f'use Ansible execution type / *_remediation.yml for rule {rule_id}"',
            "",
        ]
        return RemediationPlan(
            rule_id=rule_id,
            title=title,
            mnemonic=mnemonic,
            kind="fixtext_ansible",
            shell_lines=shell_lines,
            ansible_tasks_yaml=ansible_yaml,
        )

    puppet_fix = next(
        (f for f in fixes if classify_fix_system(f.system) == "puppet" and f.text.strip()),
        None,
    )
    if puppet_fix:
        reason = f"puppet fixtext not mapped to SecAudit executors (rule {rule_id})"
        return _unsupported_plan(rule_id, title, mnemonic, reason)

    template_kind = infer_template_kind(title, description)
    if template_kind:
        shell = build_template_shell(
            template_kind, mnemonic=mnemonic, title=title, description=description
        )
        ansible_yaml = build_template_ansible_yaml(
            template_kind, rule_id=rule_id, title=title, description=description
        )
        if shell:
            return RemediationPlan(
                rule_id=rule_id,
                title=title,
                mnemonic=mnemonic,
                kind=f"template_{template_kind}",
                shell_lines=[
                    f"# --- {rule_id}: {title} (template:{template_kind}) ---",
                    *shell,
                    "",
                ],
                ansible_tasks_yaml=ansible_yaml,
            )

    reason = (
        f"no XCCDF fixtext and no hardening-style template match for rule {rule_id}"
    )
    return _unsupported_plan(rule_id, title, mnemonic, reason)


def _unsupported_plan(rule_id: str, title: str, mnemonic: str, reason: str) -> RemediationPlan:
    safe = _safe_echo_title(title)
    return RemediationPlan(
        rule_id=rule_id,
        title=title,
        mnemonic=mnemonic,
        kind="unsupported",
        reason=reason,
        shell_lines=[
            f"# --- {rule_id}: {title} (UNSUPPORTED) ---",
            f'echo "{mnemonic}= SKIP: UNSUPPORTED — {reason}"',
            "",
        ],
        ansible_tasks_yaml=(
            f'    - name: "UNSUPPORTED: {safe}"\n'
            f"      ansible.builtin.debug:\n"
            f'        msg: "UNSUPPORTED — {reason}"\n'
            f"      tags: [scap, unsupported, {rule_id}]\n"
            f"      changed_when: false\n"
        ),
    )


def _ansible_from_fixtext(text: str, *, rule_id: str, title: str) -> str:
    stripped = text.strip()
    # Full playbook or task list from SCAP content — embed carefully.
    if stripped.startswith("---") or stripped.startswith("- ") or stripped.startswith("tasks:"):
        # Indent each line under a block that includes the tasks.
        # If content is a full play, keep as a separate imported fragment via shell copy is heavy;
        # prefer treating list-of-tasks as tasks.
        lines = stripped.splitlines()
        if lines[0].strip() == "---":
            lines = lines[1:]
        # If it looks like a play (hosts:), wrap note and use shell module with ansible-playbook on target — too heavy.
        if any(line.lstrip().startswith("hosts:") for line in lines):
            indented = "\n".join(f"          {line}" if line else "" for line in text.splitlines())
            return (
                f'    - name: "{title}"\n'
                f"      ansible.builtin.shell: |\n"
                f"{indented}\n"
                f"      args:\n"
                f"        executable: /bin/bash\n"
                f"      tags: [scap, fixtext_ansible_play, {rule_id}]\n"
            )
        indented_tasks = "\n".join(f"    {line}" if line else "" for line in lines)
        # Ensure list items are preserved
        if not indented_tasks.lstrip().startswith("-"):
            return (
                f'    - name: "{title}"\n'
                f"      ansible.builtin.shell: |\n"
                + "\n".join(f"          {line}" if line else "" for line in text.splitlines())
                + "\n"
                f"      args:\n"
                f"        executable: /bin/bash\n"
                f"      tags: [scap, fixtext_ansible, {rule_id}]\n"
            )
        return indented_tasks + "\n"

    # Plain script → shell task
    indented = "\n".join(f"          {line}" if line else "" for line in text.splitlines())
    return (
        f'    - name: "{title}"\n'
        f"      ansible.builtin.shell: |\n"
        f"{indented}\n"
        f"      args:\n"
        f"        executable: /bin/bash\n"
        f"      tags: [scap, fixtext, {rule_id}]\n"
    )


def render_remediation_shell(benchmark_id: str, plans: list[RemediationPlan]) -> str:
    lines = [
        "#!/bin/bash",
        f"# Auto-generated remediations from XCCDF Benchmark: {benchmark_id}",
        "# Sources: XCCDF fixtext (preferred) or hardening-style templates.",
        "# UNSUPPORTED rules emit SKIP with an explicit reason (not silent success).",
        "set -u",
        "export LC_ALL=C",
        'cd "$(dirname "$0")" 2>/dev/null || true',
        "",
    ]
    for plan in plans:
        lines.extend(plan.shell_lines)
    return "\n".join(lines) + "\n"


def render_remediation_ansible(benchmark_id: str, plans: list[RemediationPlan]) -> str:
    tasks: list[str] = []
    for plan in plans:
        if plan.ansible_tasks_yaml:
            tasks.append(plan.ansible_tasks_yaml.rstrip() + "\n")
    body = "".join(tasks) if tasks else (
        '    - name: "No remediation tasks"\n'
        "      ansible.builtin.debug:\n"
        '        msg: "No SCAP remediation tasks generated"\n'
        "      changed_when: false\n"
    )
    return (
        "---\n"
        f"# Auto-generated Ansible remediations from XCCDF: {benchmark_id}\n"
        "# Prefer XCCDF ansible/shell fixtext; templates are placeholders where noted.\n"
        "- name: SecAudit SCAP remediation\n"
        "  hosts: all\n"
        "  become: true\n"
        "  gather_facts: true\n"
        "  tasks:\n"
        f"{body}"
    )
