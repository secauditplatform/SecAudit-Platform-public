"""Server-side allowlist for the interactive /console WebSocket."""

from __future__ import annotations

import os
import re
import shlex

# Network diagnostics only — enforced before any subprocess spawn.
ALLOWED_COMMANDS: frozenset[str] = frozenset(
    {
        "arp",
        "dig",
        "host",
        "hostname",
        "ifconfig",
        "ip",
        "netstat",
        "nslookup",
        "ping",
        "route",
        "ss",
        "traceroute",
        "tracert",
        "whois",
    }
)

# Public demo stand: only ICMP reachability for a live terminal demo.
DEMO_ALLOWED_COMMANDS: frozenset[str] = frozenset({"ping"})

BLOCKED_SHELL_METACHAR = re.compile(r"[;|&<>`$]|&&|\|\||\$\(")
_BLOCKED_OPTIONS = {
    "arp": {"-d", "-s", "-f"},
    "dig": {"-f", "-k"},
    "host": {"-f"},
    "ip": {"-batch", "-force", "-netns"},
    "netstat": {"-M"},
    "ping": {"-f", "-l"},
    "route": {"add", "del", "delete", "flush"},
    "ss": {"-K", "--kill", "-F", "--filter"},
    "traceroute": {"--sport"},
    "whois": {"--config"},
}
_IP_READ_OBJECTS = {
    "addr",
    "address",
    "link",
    "route",
    "rule",
    "neigh",
    "neighbor",
    "netns",
    "maddr",
    "tunnel",
    "monitor",
}
_IP_READ_ACTIONS = {"show", "list", "get", "help"}

COMMAND_DENIED_EN = (
    "Command not allowed: only network diagnostics commands are permitted"
)
COMMAND_DENIED_RU = (
    "Команда запрещена: разрешены только команды сетевой диагностики"
)
COMMAND_DENIED_MESSAGE = f"{COMMAND_DENIED_EN} / {COMMAND_DENIED_RU}"
DEMO_COMMAND_DENIED_EN = "Command not allowed: demo stand permits only ping"
DEMO_COMMAND_DENIED_RU = "Команда запрещена: на демо-стенде разрешён только ping"
DEMO_COMMAND_DENIED_MESSAGE = f"{DEMO_COMMAND_DENIED_EN} / {DEMO_COMMAND_DENIED_RU}"


def validate_console_command(line: str, *, demo_mode: bool = False) -> tuple[bool, str | None]:
    """Return (allowed, error_message). Empty lines and comments are allowed."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return True, None

    denied = DEMO_COMMAND_DENIED_MESSAGE if demo_mode else COMMAND_DENIED_MESSAGE
    allowed_commands = DEMO_ALLOWED_COMMANDS if demo_mode else ALLOWED_COMMANDS

    if BLOCKED_SHELL_METACHAR.search(stripped):
        return False, denied

    try:
        tokens = shlex.split(stripped)
    except ValueError:
        return False, denied

    if not tokens:
        return True, None

    command = os.path.basename(tokens[0])
    if command != tokens[0] or tokens[0].startswith("."):
        return False, denied

    if command not in allowed_commands:
        return False, denied

    args = tokens[1:]
    blocked = _BLOCKED_OPTIONS.get(command, set())
    if any(token in blocked or any(token.startswith(f"{item}=") for item in blocked) for token in args):
        return False, denied

    # Reject control characters, paths and response-file conventions in every operand.
    if any(
        "\x00" in token
        or token.startswith("@")
        or "/" in token
        or "\\" in token
        for token in args
    ):
        return False, denied

    if command == "hostname" and any(not token.startswith("-") for token in args):
        return False, denied
    if command == "ifconfig":
        operands = [token.lower() for token in args if not token.startswith("-")]
        if len(operands) > 1 or any(
            token in {"up", "down", "add", "del", "delete", "hw", "mtu", "netmask"}
            for token in operands
        ):
            return False, denied
    if command == "ip":
        operands = [token.lower() for token in args if not token.startswith("-")]
        if operands:
            if operands[0] not in _IP_READ_OBJECTS:
                return False, denied
            if len(operands) > 1 and operands[1] not in _IP_READ_ACTIONS:
                # "ip route 1.2.3.4" is not a valid read form; require explicit get/show.
                return False, denied
        if "netns" in operands and (len(operands) < 2 or operands[1] != "list"):
            return False, denied
    if command == "route" and any(
        token.lower() in {"add", "del", "delete", "flush"} for token in args
    ):
        return False, denied

    return True, None
