"""Policy checks that keep Ansible from becoming unsandboxed worker RCE."""

from __future__ import annotations

import re
from typing import Any

import yaml

# Controller-side lookups can read the worker environment/files; inventory and
# credential variables are equally off-limits to an operator-authored playbook.
_FORBIDDEN_TEMPLATE = re.compile(r"\b(?:lookup|query)\s*\(", re.IGNORECASE)
_FORBIDDEN_VARS = re.compile(
    r"\b(?:hostvars|ansible_password|ansible_ssh_pass|ansible_ssh_private_key_passphrase)\b",
    re.IGNORECASE,
)
_FORBIDDEN_CONNECTION_VAR = re.compile(r"\bansible_connection\b", re.IGNORECASE)
_JINJA_TEMPLATE = re.compile(r"(\{\{|\{%)")
_TASK_LIST_KEYS = ("tasks", "pre_tasks", "post_tasks", "handlers")
_CONTROLLER_FILE_MODULES = frozenset(
    {"copy", "template", "assemble", "unarchive", "script"}
)

# Local controller execution is allowed only for constrained network/audit patterns.
_LOCAL_CONNECTION_MODULES = frozenset(
    {
        "ansible.builtin.script",
        "script",
        "ansible.builtin.debug",
        "debug",
        "ansible.builtin.set_fact",
        "set_fact",
        "ansible.builtin.assert",
        "assert",
        "ansible.builtin.fail",
        "fail",
        "ansible.builtin.meta",
        "meta",
    }
)

# Tasks delegated to the worker may only run a small reachability set.
_LOCAL_DELEGATE_MODULES = frozenset(
    {
        "ansible.builtin.command",
        "command",
        "ansible.builtin.ping",
        "ping",
        "ansible.builtin.wait_for",
        "wait_for",
        "ansible.builtin.debug",
        "debug",
        "ansible.builtin.set_fact",
        "set_fact",
    }
)

_LOCAL_HOST_TOKENS = frozenset({"localhost", "127.0.0.1", "::1", "local"})

_TASK_RESERVED_KEYS = frozenset(
    {
        "name",
        "when",
        "register",
        "delegate_to",
        "become",
        "become_user",
        "become_method",
        "vars",
        "tags",
        "ignore_errors",
        "changed_when",
        "failed_when",
        "notify",
        "loop",
        "with_items",
        "with_dict",
        "with_fileglob",
        "with_together",
        "with_nested",
        "with_subelements",
        "with_sequence",
        "with_random_choice",
        "with_first_found",
        "with_indexed_items",
        "with_ini",
        "with_inventory_hostnames",
        "with_lines",
        "with_flattened",
        "args",
        "environment",
        "retries",
        "delay",
        "until",
        "block",
        "rescue",
        "always",
        "listen",
        "run_once",
        "check_mode",
        "diff",
        "throttle",
        "timeout",
        "any_errors_fatal",
        "local_action",
        "remote_user",
        "connection",
        "port",
        "vars_files",
        "module_defaults",
        "collections",
        "debugger",
        "ignore_unreachable",
        "no_log",
        "loop_control",
    }
)


class PlaybookSecurityError(ValueError):
    """Raised when a playbook violates the local-execution security policy."""


def _normalize_module(name: str) -> str:
    return str(name or "").strip().lower()


def _host_token_is_local(token: str) -> bool:
    return str(token or "").strip().lower() in _LOCAL_HOST_TOKENS


def _hosts_are_localhost_only(hosts: Any) -> bool:
    if hosts is None:
        return False
    if isinstance(hosts, list):
        tokens = [str(item).strip() for item in hosts if str(item).strip()]
    else:
        tokens = [part.strip() for part in str(hosts).split(",") if part.strip()]
    if not tokens:
        return False
    return all(_host_token_is_local(token) for token in tokens)


def _delegate_is_local(delegate_to: Any) -> bool:
    if delegate_to is None:
        return False
    return _host_token_is_local(str(delegate_to))


def _play_uses_local_connection(play: dict[str, Any]) -> bool:
    connection = play.get("connection")
    if connection is not None and _normalize_module(str(connection)) == "local":
        return True
    vars_block = play.get("vars")
    if isinstance(vars_block, dict):
        ansible_connection = vars_block.get("ansible_connection")
        if ansible_connection is not None and _normalize_module(str(ansible_connection)) == "local":
            return True
    return False


def _task_uses_local_connection(task: dict[str, Any]) -> bool:
    connection = task.get("connection")
    if connection is not None and _normalize_module(str(connection)) == "local":
        return True
    vars_block = task.get("vars")
    if not isinstance(vars_block, dict):
        return False
    ansible_connection = vars_block.get("ansible_connection")
    return ansible_connection is not None and _normalize_module(str(ansible_connection)) == "local"


def _assert_no_jinja_in_connection_fields(task: dict[str, Any], context: str) -> None:
    for key in ("connection", "delegate_to"):
        value = task.get(key)
        if value is None:
            continue
        text = str(value)
        if _JINJA_TEMPLATE.search(text):
            raise PlaybookSecurityError(
                f"{context}: Jinja templates are forbidden in '{key}'"
            )


def _task_module_name(task: dict[str, Any]) -> str | None:
    if "action" in task:
        action = task["action"]
        if isinstance(action, str):
            return _normalize_module(action.split()[0])
        if isinstance(action, dict):
            module = action.get("module") or action.get("ansible.builtin.module")
            if module:
                return _normalize_module(str(module))
    for key in task:
        if key in _TASK_RESERVED_KEYS or key.startswith("with_"):
            continue
        return _normalize_module(key)
    return None


def _script_ref_is_safe(task: dict[str, Any]) -> bool:
    """Script module on the controller may only reference a relative basename."""
    raw = task.get("ansible.builtin.script", task.get("script"))
    if isinstance(raw, dict):
        raw = raw.get("cmd") or raw.get("_raw_params") or next(iter(raw.values()), None)
    text = str(raw or "").strip()
    if not text:
        return False
    if "/" in text or "\\" in text or text.startswith("~"):
        return False
    name = text.split()[0]
    if name in {".", ".."} or ".." in name:
        return False
    return bool(name)


def _command_is_ping_only(task: dict[str, Any]) -> bool:
    raw = task.get("ansible.builtin.command", task.get("command"))
    if isinstance(raw, dict):
        raw = raw.get("cmd") or raw.get("_raw_params") or next(iter(raw.values()), None)
    text = str(raw or "").strip().lower()
    if not text:
        return False
    # Allow only ICMP reachability helpers used by network templates.
    return text.startswith("ping ") or text == "ping" or text.startswith("ping\t")


def _iter_task_dicts(nodes: Any) -> list[dict[str, Any]]:
    if nodes is None:
        return []
    if not isinstance(nodes, list):
        return []
    out: list[dict[str, Any]] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if "block" in node or "rescue" in node or "always" in node:
            out.extend(_iter_task_dicts(node.get("block")))
            out.extend(_iter_task_dicts(node.get("rescue")))
            out.extend(_iter_task_dicts(node.get("always")))
            continue
        out.append(node)
    return out


def _assert_local_task_allowed(
    task: dict[str, Any],
    *,
    allowed_modules: frozenset[str],
    context: str,
) -> None:
    if "local_action" in task:
        raise PlaybookSecurityError(
            f"{context}: local_action is forbidden (unsandboxed worker execution)"
        )

    module = _task_module_name(task)
    if not module:
        return
    if module not in allowed_modules:
        raise PlaybookSecurityError(
            f"{context}: module '{module}' is not allowed for local worker execution"
        )
    if module in {"ansible.builtin.script", "script"} and not _script_ref_is_safe(task):
        raise PlaybookSecurityError(
            f"{context}: script module on the worker must use a relative basename only"
        )
    if module in {"ansible.builtin.command", "command"} and not _command_is_ping_only(task):
        raise PlaybookSecurityError(
            f"{context}: command module on the worker may only run ping"
        )


def _controller_src(module: str, args: Any) -> str | None:
    if isinstance(args, dict):
        if args.get("remote_src") is True:
            return None
        for key in ("src", "cmd"):
            if key in args and args[key] is not None:
                return str(args[key])
        return None
    text = str(args or "").strip()
    if not text:
        return None
    if module == "script":
        return text.split()[0]
    match = re.search(r"(?:^|\s)src\s*=\s*(\S+)", text)
    return match.group(1) if match else None


def _assert_no_controller_file_read(task: dict[str, Any], context: str) -> None:
    """Reject copy/template/script reads from absolute or traversal paths."""
    for key, args in task.items():
        if not isinstance(key, str):
            continue
        module = key.rsplit(".", 1)[-1]
        if module not in _CONTROLLER_FILE_MODULES:
            continue
        src = _controller_src(module, args)
        if src is None:
            continue
        cleaned = src.strip().strip("'\"")
        parts = cleaned.replace("\\", "/").split("/")
        if (
            cleaned.startswith(("/", "~"))
            or ".." in parts
            or "{{" in cleaned
            or "{%" in cleaned
        ):
            raise PlaybookSecurityError(
                f"{context}: {module} may only use a relative package file as src"
            )


def assert_playbook_local_execution_policy(content: str) -> None:
    """Reject playbooks that would run unconstrained code on the Ansible controller.

    Network compliance packages may use ``hosts: localhost`` + ``connection: local``
    with an allowlisted module set (script/debug/set_fact/...). User playbooks that
    set ``connection: local`` on ``hosts: all`` or use shell/raw/copy on localhost
    are rejected at validate and runtime.
    """
    if _FORBIDDEN_TEMPLATE.search(content or ""):
        raise PlaybookSecurityError(
            "lookup/query is forbidden in playbooks (controller-side data access)"
        )
    if _FORBIDDEN_VARS.search(content or ""):
        raise PlaybookSecurityError(
            "hostvars and credential variables are forbidden in playbooks"
        )
    if _FORBIDDEN_CONNECTION_VAR.search(content or ""):
        raise PlaybookSecurityError(
            "ansible_connection variable is forbidden; use the play-level connection keyword"
        )
    try:
        loaded = yaml.safe_load(content or "")
    except yaml.YAMLError as exc:
        raise PlaybookSecurityError(f"Invalid playbook YAML: {exc}") from exc

    if loaded is None:
        return
    plays: list[Any]
    if isinstance(loaded, dict):
        plays = [loaded]
    elif isinstance(loaded, list):
        plays = loaded
    else:
        raise PlaybookSecurityError("Playbook YAML must be a list of plays or a mapping")

    for index, play in enumerate(plays, start=1):
        if not isinstance(play, dict):
            continue
        context = f"Play #{index}"
        play_name = play.get("name")
        if play_name:
            context = f"Play #{index} ({play_name})"
        if isinstance(play.get("vars"), dict) and "ansible_connection" in play["vars"]:
            raise PlaybookSecurityError(
                f"{context}: ansible_connection in vars is forbidden; use the play-level connection keyword"
            )

        if play.get("roles"):
            raise PlaybookSecurityError(
                f"{context}: roles: is forbidden (role tasks bypass the local-execution scanner)"
            )

        play_local_connection = _play_uses_local_connection(play)
        hosts_localhost = _hosts_are_localhost_only(play.get("hosts"))
        if play_local_connection and not hosts_localhost:
            raise PlaybookSecurityError(
                f"{context}: connection: local is only allowed with hosts: localhost "
                "(refusing hosts that would execute on the worker for inventory targets)"
            )
        play_connection = play.get("connection")
        if play_connection is not None and _JINJA_TEMPLATE.search(str(play_connection)):
            raise PlaybookSecurityError(
                f"{context}: Jinja templates are forbidden in play-level 'connection'"
            )

        for list_key in _TASK_LIST_KEYS:
            for task in _iter_task_dicts(play.get(list_key)):
                task_name = str(task.get("name") or "unnamed task")
                task_context = f"{context} / {list_key} '{task_name}'"
                if isinstance(task.get("vars"), dict) and "ansible_connection" in task["vars"]:
                    raise PlaybookSecurityError(
                        f"{task_context}: ansible_connection in task vars is forbidden"
                    )
                if "local_action" in task:
                    raise PlaybookSecurityError(
                        f"{task_context}: local_action is forbidden (unsandboxed worker execution)"
                    )
                _assert_no_jinja_in_connection_fields(task, task_context)

                task_local = _task_uses_local_connection(task)
                if task_local and not hosts_localhost and not play_local_connection:
                    # Task-level connection: local on remote inventory is worker RCE.
                    raise PlaybookSecurityError(
                        f"{task_context}: connection: local is only allowed with hosts: localhost"
                    )

                local_connection = play_local_connection or hosts_localhost or task_local
                delegated_local = _delegate_is_local(task.get("delegate_to"))

                if not local_connection and not delegated_local:
                    _assert_no_controller_file_read(task, task_context)

                if local_connection:
                    _assert_local_task_allowed(
                        task,
                        allowed_modules=_LOCAL_CONNECTION_MODULES,
                        context=task_context,
                    )
                elif delegated_local:
                    _assert_local_task_allowed(
                        task,
                        allowed_modules=_LOCAL_DELEGATE_MODULES,
                        context=task_context,
                    )
