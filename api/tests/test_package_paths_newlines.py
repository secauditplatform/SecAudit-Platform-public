from pathlib import Path

from secaudit_core.package_paths import (
    normalize_shell_script_bytes,
    normalize_shell_script_file,
    normalize_shell_scripts_in_tree,
    normalize_text_newlines,
    replace_package_tree,
)


def test_normalize_text_newlines():
    assert normalize_text_newlines("a\r\nb\rc\n") == "a\nb\nc\n"


def test_normalize_shell_script_bytes():
    assert normalize_shell_script_bytes(b"#!/bin/bash\r\necho hi\r\n") == b"#!/bin/bash\necho hi\n"
    assert normalize_shell_script_bytes(b"already\nunix\n") == b"already\nunix\n"


def test_normalize_shell_script_file(tmp_path: Path):
    path = tmp_path / "fix.sh"
    path.write_bytes(b"#!/bin/bash\r\npkg_install() {\r\n  true\r\n}\r\n")
    assert normalize_shell_script_file(path) is True
    assert path.read_bytes() == b"#!/bin/bash\npkg_install() {\n  true\n}\n"
    assert normalize_shell_script_file(path) is False


def test_normalize_shell_scripts_in_tree(tmp_path: Path):
    shell = tmp_path / "remediation.sh"
    other = tmp_path / "notes.txt"
    shell.write_bytes(b"echo 1\r\n")
    other.write_bytes(b"keep\r\nwindows\r\n")
    assert normalize_shell_scripts_in_tree(tmp_path) == 1
    assert shell.read_bytes() == b"echo 1\n"
    assert other.read_bytes() == b"keep\r\nwindows\r\n"


def test_replace_package_tree_skips_pycache_and_replaces_dest(tmp_path: Path):
    source = tmp_path / "src"
    dest = tmp_path / "dest"
    source.mkdir()
    (source / "check.py").write_text("print(1)\n", encoding="utf-8")
    (source / "__pycache__").mkdir()
    (source / "__pycache__" / "check.cpython-312.pyc").write_bytes(b"cache")
    dest.mkdir()
    leftover = dest / "__pycache__"
    leftover.mkdir()
    (leftover / "old.pyc").write_bytes(b"old")
    (dest / "stale.py").write_text("old\n", encoding="utf-8")

    result = replace_package_tree(source, dest)
    assert result == dest
    assert (dest / "check.py").read_text(encoding="utf-8") == "print(1)\n"
    assert not (dest / "stale.py").exists()
    assert not (dest / "__pycache__").exists()


def test_replace_package_tree_inplace_when_parent_not_writable(tmp_path: Path, monkeypatch):
    storage = tmp_path / "storage"
    storage.mkdir()
    source = tmp_path / "src"
    dest = storage / "pkg"
    source.mkdir()
    (source / "rules.json").write_text('{"ok": true}\n', encoding="utf-8")
    dest.mkdir()
    (dest / "old.txt").write_text("old\n", encoding="utf-8")

    real_copytree = __import__("shutil").copytree

    def _copytree(src, dst, *args, **kwargs):
        dst_path = Path(dst)
        if dst_path.parent == storage and dst_path.name.startswith(".pkg.tmp-"):
            raise PermissionError("parent not writable")
        return real_copytree(src, dst, *args, **kwargs)

    monkeypatch.setattr("secaudit_core.package_paths.shutil.copytree", _copytree)

    result = replace_package_tree(source, dest)
    assert result == dest
    assert (dest / "rules.json").read_text(encoding="utf-8") == '{"ok": true}\n'
    assert not (dest / "old.txt").exists()
    assert not any(path.name.startswith(".sync-tmp-") for path in dest.iterdir())
