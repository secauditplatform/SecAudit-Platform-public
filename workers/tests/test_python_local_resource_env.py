import os
from pathlib import Path

import pytest

from app.executors.python_exec import run_script_locally_with_resource_env


def test_run_script_locally_injects_resource_env(tmp_path: Path):
    script = tmp_path / "check.py"
    script.write_text(
        "import os\n"
        "print(f\"ip={os.environ.get('resource_ip')}\")\n"
        "print(f\"user={os.environ.get('resource_user')}\")\n"
        "print(f\"port={os.environ.get('resource_port')}\")\n"
        "print(f\"pass={os.environ.get('resource_pass')}\")\n",
        encoding="utf-8",
    )

    output = run_script_locally_with_resource_env(
        hostname="10.1.2.3",
        port=2222,
        username="netadmin",
        password="s3cret",
        private_key=None,
        script_path=script,
        timeout=30,
    )
    assert "ip=10.1.2.3" in output
    assert "user=netadmin" in output
    assert "port=2222" in output
    assert "pass=s3cret" in output


def test_run_script_locally_writes_key_file(tmp_path: Path):
    script = tmp_path / "check.py"
    script.write_text(
        "import os\n"
        "path = os.environ.get('ssh_private_key_path')\n"
        "print(f'key_path={path}')\n"
        "print(open(path, encoding='utf-8').read().strip())\n",
        encoding="utf-8",
    )

    output = run_script_locally_with_resource_env(
        hostname="device.example",
        port=22,
        username="admin",
        password=None,
        private_key="-----BEGIN KEY-----\nabc\n-----END KEY-----",
        script_path=script,
        timeout=30,
    )
    assert "key_path=" in output
    assert "-----BEGIN KEY-----" in output
    # Temp key must be cleaned up after the run.
    key_line = next(line for line in output.splitlines() if line.startswith("key_path="))
    key_path = Path(key_line.split("=", 1)[1])
    assert not key_path.exists()


def test_run_script_locally_nonzero_exit_raises(tmp_path: Path):
    script = tmp_path / "boom.py"
    script.write_text("import sys\nprint('partial')\nsys.exit(7)\n", encoding="utf-8")
    with pytest.raises(RuntimeError) as exc:
        run_script_locally_with_resource_env(
            hostname="h",
            port=22,
            username="u",
            password="p",
            private_key=None,
            script_path=script,
            timeout=30,
        )
    assert "code 7" in str(exc.value)
    assert "partial" in str(exc.value)


def test_run_script_locally_does_not_write_bytecode(tmp_path: Path):
    helper = tmp_path / "helper.py"
    helper.write_text("VALUE = 1\n", encoding="utf-8")
    script = tmp_path / "check.py"
    script.write_text("import helper\nprint(helper.VALUE)\n", encoding="utf-8")

    output = run_script_locally_with_resource_env(
        hostname="h",
        port=22,
        username="u",
        password="p",
        private_key=None,
        script_path=script,
        timeout=30,
    )
    assert "1" in output
    assert not (tmp_path / "__pycache__").exists()
