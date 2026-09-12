import re
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from secaudit_core.interpreter import apply_interpreter_rules as apply_interpreter_rules
from secaudit_core.profile_packages import (
    EXCLUDED_SCRIPT_MARKERS,
    REMEDIATION_SCRIPT_MARKER,
    SCRIPT_EXTENSIONS,
    _find_profile_file,
    discover_check_scripts,
    discover_remediation_scripts,
    execution_type_for_extension,
    infer_category_from_package_dir,
    infer_category_slug,
    load_profile_package,
    load_profile_rules_metadata,
    load_rule_changelog,
    map_execution_type,
    package_encoding_hint,
    profile_name_from_meta,
    DEFAULT_PROFILE_VERSION,
    read_package_text_file,
    update_profile_rule_in_package,
    validate_profile_package,
)

from app.models import CheckStatus, ExecutionType

MAX_UPLOAD_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_FILES = 500


def parse_check_line(line: str) -> tuple[str | None, CheckStatus | None, str | None]:
    """Parse output line like: RULE1= PASS: description"""
    match = re.match(
        r"^(?:RULE|REQ)\d+\s*=\s*(PASS|FAIL|SKIP|ERROR)\s*:\s*(.*)$",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return None, None, None
    status_map = {
        "PASS": CheckStatus.PASS,
        "FAIL": CheckStatus.FAIL,
        "SKIP": CheckStatus.SKIP,
        "ERROR": CheckStatus.ERROR,
    }
    return None, status_map.get(match.group(1).upper()), match.group(2).strip()


def _safe_extract_zip(archive: zipfile.ZipFile, dest: Path) -> None:
    if len(archive.namelist()) > MAX_ARCHIVE_FILES:
        raise ValueError("Archive contains too many files")
    dest_root = dest.resolve()
    for member in archive.namelist():
        target = (dest / member).resolve()
        if dest_root not in target.parents and target != dest_root:
            raise ValueError(f"Unsafe archive path: {member}")
    archive.extractall(dest)


def _safe_extract_tar(archive: tarfile.TarFile, dest: Path) -> None:
    if len(archive.getmembers()) > MAX_ARCHIVE_FILES:
        raise ValueError("Archive contains too many files")
    dest_root = dest.resolve()
    for member in archive.getmembers():
        if member.issym() or member.islnk() or member.isdev() or member.isfifo():
            raise ValueError(f"Unsafe archive member type: {member.name}")
        target = (dest / member.name).resolve()
        if dest_root not in target.parents and target != dest_root:
            raise ValueError(f"Unsafe archive path: {member.name}")
    # Python 3.12+: data filter blocks symlink/absolute escape during extract.
    if hasattr(tarfile, "data_filter"):
        archive.extractall(dest, filter="data")
    else:
        archive.extractall(dest)


def _resolve_package_root(extracted_dir: Path) -> Path:
    entries = [item for item in extracted_dir.iterdir() if item.name != "__MACOSX"]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return extracted_dir


def _write_upload_file(dest: Path, filename: str, content: bytes) -> None:
    relative = PurePosixPath(filename.replace("\\", "/"))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"Unsafe file path: {filename}")
    target = (dest / relative).resolve()
    if dest.resolve() not in target.parents:
        raise ValueError(f"Unsafe file path: {filename}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)


def materialize_uploaded_package(
    uploads: list[tuple[str, bytes]],
) -> tuple[Path, tempfile.TemporaryDirectory[str]]:
    if not uploads:
        raise ValueError("No files uploaded")

    total_size = sum(len(content) for _, content in uploads)
    if total_size > MAX_UPLOAD_BYTES:
        raise ValueError(f"Upload exceeds maximum size of {MAX_UPLOAD_BYTES} bytes")

    temp_dir = tempfile.TemporaryDirectory(prefix="secaudit-import-")
    root = Path(temp_dir.name)

    if len(uploads) == 1:
        filename, content = uploads[0]
        lowered = filename.lower()
        if lowered.endswith(".zip"):
            archive_path = root / "upload.zip"
            archive_path.write_bytes(content)
            extract_to = root / "extracted"
            extract_to.mkdir()
            with zipfile.ZipFile(archive_path) as archive:
                _safe_extract_zip(archive, extract_to)
            return _resolve_package_root(extract_to), temp_dir
        if lowered.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2")):
            suffix = ".tar.gz" if lowered.endswith(".tar.gz") else Path(lowered).suffix or ".tar"
            archive_path = root / f"upload{suffix}"
            archive_path.write_bytes(content)
            extract_to = root / "extracted"
            extract_to.mkdir()
            with tarfile.open(archive_path) as archive:
                _safe_extract_tar(archive, extract_to)
            return _resolve_package_root(extract_to), temp_dir

    flat_root = root / "package"
    flat_root.mkdir()
    for filename, content in uploads:
        _write_upload_file(flat_root, filename, content)
    return flat_root, temp_dir


# Compatibility alias
package_charset_hint = package_encoding_hint
