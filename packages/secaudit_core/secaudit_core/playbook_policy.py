"""Static policy checks for Ansible playbook YAML (worker isolation)."""

from __future__ import annotations

import re
from typing import Any

# Short names after FQCN normalization (ansible.builtin.local → local).
_BLOCKED_CONNECTIONS = frozenset(
    {
        "local",
        "chroot",
        "jail",
        "docker",
        "podman",
        "buildah",
        "community.docker.docker",
        "containers.podman.podman",
    }
)

_LOCAL_DELEGATE_TARGETS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
    }
)

# Modules allowed with delegate_to localhost (diagnostics only).
_LOCAL_DELEGATE_SAFE_MODULES = frozenset(
    {
        "ansible.builtin.debug",
        "ansible.builtin.set_fact",
        "ansible.builtin.assert",
        "ansible.builtin.ping",
        "ansible.builtin.command",
        "debug",
        "set_fact",
        "assert",
        "ping",
        "command",
    }
)

# Dynamic includes hide tasks from static policy — reject outright.
_BLOCKED_INCLUDE_MODULES = frozenset(
    {
        "import_tasks",
        "include_tasks",
        "import_playbook",
        "include",
        "include_role",
        "import_role",
        "ansible.builtin.import_tasks",
        "ansible.builtin.include_tasks",
        "ansible.builtin.import_playbook",
        "ansible.builtin.include",
        "ansible.builtin.include_role",
        "ansible.builtin.import_role",
        "ansible.legacy.import_tasks",
        "ansible.legacy.include_tasks",
        "ansible.legacy.import_playbook",
        "ansible.legacy.include",
        "ansible.legacy.include_role",
        "ansible.legacy.import_role",
    }
)

# Always-dangerous controller-side patterns even when not explicitly local.
_BLOCKED_MODULES = frozenset(
    {
        "ansible.builtin.meta",
        "meta",
        "ansible.builtin.include_vars",
        "include_vars",
        "ansible.builtin.add_host",
        "add_host",
        "ansible.builtin.group_by",
        "group_by",
        *_BLOCKED_INCLUDE_MODULES,
    }
)

_BLOCKED_LOCAL_ACTION_MODULES = frozenset(
    {
        "ansible.builtin.shell",
        "ansible.builtin.raw",
        "ansible.builtin.script",
        "ansible.builtin.copy",
        "ansible.builtin.file",
        "ansible.builtin.template",
        "ansible.builtin.unarchive",
        "ansible.builtin.get_url",
        "ansible.builtin.uri",
        "ansible.builtin.pip",
        "ansible.builtin.apt",
        "ansible.builtin.yum",
        "ansible.builtin.dnf",
        "ansible.builtin.package",
        "ansible.builtin.service",
        "ansible.builtin.systemd",
        "ansible.builtin.user",
        "ansible.builtin.group",
        "ansible.builtin.cron",
        "ansible.builtin.lineinfile",
        "ansible.builtin.blockinfile",
        "ansible.builtin.replace",
        "shell",
        "raw",
        "script",
        "copy",
        "file",
        "template",
        "unarchive",
        "get_url",
        "uri",
        "pip",
        "apt",
        "yum",
        "dnf",
        "package",
        "service",
        "systemd",
        "user",
        "group",
        "cron",
        "lineinfile",
        "blockinfile",
        "replace",
    }
)

# Jinja expressions that execute on the Ansible controller regardless of connection.
_CONTROLLER_JINJA_RE = re.compile(
    r"(?is)"
    r"(?:\{\{|\{%).*?\b(?:lookup|query)\s*\("
    r"|\{\{\s*q\s*\("
)


def _as_plays(loaded: Any) -> list[dict[str, Any]]:
    if isinstance(loaded, dict):
        return [loaded]
    if isinstance(loaded, list):
        return [item for item in loaded if isinstance(item, dict)]
    raise ValueError("Playbook YAML must be a list of plays or a mapping")


def _normalize_plugin_name(value: Any) -> str:
    """Lowercase and strip common Ansible collection prefixes for comparison."""
    text = str(value or "").strip().lower()
    for prefix in ("ansible.builtin.", "ansible.legacy.", "ansible."):
        if text.startswith(prefix):
            return text[len(prefix) :]
    return text


def _connection_name(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if text in _BLOCKED_CONNECTIONS:
        return text
    return _normalize_plugin_name(text)


def _task_module_name(task: dict[str, Any]) -> str | None:
    if "action" in task and isinstance(task["action"], str):
        return task["action"].split()[0].strip()
    skip = {
        "name",
        "when",
        "register",
        "changed_when",
        "failed_when",
        "ignore_errors",
        "delegate_to",
        "delegate_facts",
        "become",
        "become_user",
        "become_method",
        "vars",
        "tags",
        "loop",
        "with_items",
        "with_dict",
        "with_fileglob",
        "with_lines",
        "notify",
        "listen",
        "retries",
        "delay",
        "until",
        "environment",
        "args",
        "local_action",
        "connection",
        "remote_user",
        "run_once",
        "check_mode",
        "diff",
        "no_log",
        "throttle",
        "async",
        "poll",
        "block",
        "rescue",
        "always",
    }
    for key, value in task.items():
        if key in skip or key.startswith("with_"):
            continue
        if isinstance(value, (str, dict, list, int, bool)) or value is None:
            return str(key)
    return None


def _iter_tasks(node: Any) -> list[dict[str, Any]]:
    tasks: list[dict[str, Any]] = []
    if isinstance(node, dict):
        for key in ("tasks", "pre_tasks", "post_tasks", "handlers"):
            items = node.get(key)
            if isinstance(items, list):
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    tasks.append(item)
                    for nested_key in ("block", "rescue", "always"):
                        nested = item.get(nested_key)
                        if isinstance(nested, list):
                            tasks.extend(_iter_tasks({nested_key: nested}))
        for nested_key in ("block", "rescue", "always"):
            nested = node.get(nested_key)
            if isinstance(nested, list):
                for item in nested:
                    if isinstance(item, dict):
                        tasks.append(item)
                        tasks.extend(_iter_tasks(item))
    elif isinstance(node, list):
        for item in node:
            tasks.extend(_iter_tasks(item))
    return tasks


def _normalize_delegate_target(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if text.startswith("{{") and text.endswith("}}"):
        # Templated delegate targets are rejected (cannot prove safety statically).
        return "__templated__"
    return text


def _command_is_safe_ping(task: dict[str, Any], module: str) -> bool:
    short = _normalize_plugin_name(module)
    if short not in {"command"} and module not in {"ansible.builtin.command", "command"}:
        return True
    raw = task.get(module)
    if raw is None:
        for key in ("ansible.builtin.command", "command"):
            if key in task:
                raw = task[key]
                break
    argv: list[str] = []
    if isinstance(raw, str):
        argv = raw.split()
    elif isinstance(raw, dict):
        if isinstance(raw.get("argv"), list):
            argv = [str(x) for x in raw["argv"]]
        elif isinstance(raw.get("cmd"), str):
            argv = str(raw["cmd"]).split()
    if not argv:
        return False
    return argv[0].lower() in {"ping", "ping.exe"}


def _hosts_include_local(hosts: Any) -> bool:
    """True if any host pattern targets controller localhost/loopback."""
    if hosts is None:
        return False
    if isinstance(hosts, str):
        parts = [p.strip().lower() for p in hosts.split(",") if p.strip()]
    elif isinstance(hosts, list):
        parts = [str(p).strip().lower() for p in hosts]
    else:
        parts = [str(hosts).strip().lower()]
    if not parts:
        return False
    return any(part in _LOCAL_DELEGATE_TARGETS for part in parts)


def _walk_strings(node: Any) -> list[str]:
    found: list[str] = []
    if isinstance(node, str):
        found.append(node)
    elif isinstance(node, dict):
        for key, value in node.items():
            found.append(str(key))
            found.extend(_walk_strings(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_walk_strings(item))
    return found


def _reject_controller_jinja(node: Any, *, play_index: int | None = None) -> None:
    prefix = f"Play #{play_index}: " if play_index is not None else ""
    for text in _walk_strings(node):
        if _CONTROLLER_JINJA_RE.search(text):
            raise ValueError(
                f"{prefix}Jinja lookup/query plugins are not allowed "
                "(execute on the SecAudit worker)"
            )


def _vars_mapping(node: Any) -> dict[str, Any]:
    if isinstance(node, dict):
        return node
    return {}


def _ansible_connection_from_vars(vars_map: dict[str, Any]) -> str | None:
    for key in ("ansible_connection", "connection"):
        if key in vars_map:
            return str(vars_map[key])
    return None


def _reject_blocked_connection(raw: Any, *, play_index: int, where: str) -> None:
    name = _connection_name(raw)
    if not name:
        return
    # Match short name and remaining FQCN forms in the blocklist.
    short = _normalize_plugin_name(name)
    if name in _BLOCKED_CONNECTIONS or short in _BLOCKED_CONNECTIONS:
        raise ValueError(
            f"Play #{play_index}: {where}={raw!r} is not allowed "
            "(runs on the SecAudit worker)"
        )


def _module_is_blocked(module: str) -> bool:
    if module in _BLOCKED_MODULES or module in _BLOCKED_INCLUDE_MODULES:
        return True
    short = _normalize_plugin_name(module)
    blocked_shorts = {_normalize_plugin_name(m) for m in _BLOCKED_MODULES}
    return short in blocked_shorts


def _module_is_local_delegate_safe(module: str) -> bool:
    if module in _LOCAL_DELEGATE_SAFE_MODULES:
        return True
    short = _normalize_plugin_name(module)
    safe_shorts = {_normalize_plugin_name(m) for m in _LOCAL_DELEGATE_SAFE_MODULES}
    if short not in safe_shorts:
        return False
    blocked_local = {_normalize_plugin_name(m) for m in _BLOCKED_LOCAL_ACTION_MODULES}
    return short not in blocked_local


def validate_playbook_policy(loaded: Any) -> None:
    """Raise ValueError if playbook would execute unsafe code on the controller/worker."""
    _reject_controller_jinja(loaded)
    plays = _as_plays(loaded)
    for index, play in enumerate(plays, start=1):
        _reject_blocked_connection(play.get("connection"), play_index=index, where="connection")
        play_vars = _vars_mapping(play.get("vars"))
        conn_from_vars = _ansible_connection_from_vars(play_vars)
        if conn_from_vars is not None:
            _reject_blocked_connection(
                conn_from_vars, play_index=index, where="vars.ansible_connection"
            )

        if _hosts_include_local(play.get("hosts")):
            raise ValueError(
                f"Play #{index}: hosts targeting localhost/loopback is not allowed"
            )

        for task in _iter_tasks(play):
            if "local_action" in task:
                raise ValueError(
                    f"Play #{index}: local_action is not allowed "
                    "(runs on the SecAudit worker)"
                )

            _reject_blocked_connection(
                task.get("connection"), play_index=index, where="task connection"
            )
            task_vars = _vars_mapping(task.get("vars"))
            task_conn_vars = _ansible_connection_from_vars(task_vars)
            if task_conn_vars is not None:
                _reject_blocked_connection(
                    task_conn_vars,
                    play_index=index,
                    where="task vars.ansible_connection",
                )

            module = _task_module_name(task)
            if module and _module_is_blocked(module):
                raise ValueError(f"Play #{index}: module {module!r} is not allowed")

            delegate = _normalize_delegate_target(task.get("delegate_to"))
            if delegate is None:
                continue
            if delegate == "__templated__":
                raise ValueError(
                    f"Play #{index}: templated delegate_to is not allowed"
                )
            if delegate not in _LOCAL_DELEGATE_TARGETS:
                continue

            if not module:
                raise ValueError(
                    f"Play #{index}: delegate_to localhost requires an explicit module"
                )
            if not _module_is_local_delegate_safe(module):
                raise ValueError(
                    f"Play #{index}: module {module!r} cannot run with "
                    "delegate_to localhost on the SecAudit worker"
                )
            if not _command_is_safe_ping(task, module):
                raise ValueError(
                    f"Play #{index}: localhost-delegated command is limited to ping"
                )


def validate_playbook_text(content: str) -> None:
    """Scan raw playbook text for controller-side Jinja before/aside from YAML load."""
    if _CONTROLLER_JINJA_RE.search(content or ""):
        raise ValueError(
            "Jinja lookup/query plugins are not allowed (execute on the SecAudit worker)"
        )
