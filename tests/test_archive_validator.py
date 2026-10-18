"""Tests for TRASHAK AI Secure ZIP Archive Validator."""

import io
import stat
import zipfile
import pytest

from backend.core.archive_validator import (
    DEFAULT_MAX_ENTRIES,
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_PATH_LENGTH,
    DEFAULT_MAX_TOTAL_SIZE,
    validate_archive,
)


def _create_zip(entries: dict) -> bytes:
    """Helper to build an in-memory ZIP archive from a dict of {path: content_bytes}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, content in entries.items():
            zf.writestr(path, content)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Valid Archives
# ---------------------------------------------------------------------------


def test_valid_zip_single_file():
    """Ensure a simple valid archive passes all checks."""
    archive_data = _create_zip({"main.py": b"print('Hello, TRASHAK AI!')\n"})
    result = validate_archive(archive_data)

    assert result["valid"] is True
    assert result["file_count"] == 1
    assert result["total_uncompressed_size"] == len(b"print('Hello, TRASHAK AI!')\n")
    assert result["issues"] == []


def test_valid_zip_multiple_files_and_directories():
    """Ensure an archive with nested directories and files validates correctly."""
    entries = {
        "src/": b"",
        "src/app.py": b"import sys\nprint(sys.version)",
        "src/utils.py": b"def add(a, b): return a + b",
        "docs/": b"",
        "docs/guide.md": b"# User Guide\nDocumentation here.",
        "README.md": b"# Project\nReadme content.",
    }
    archive_data = _create_zip(entries)
    result = validate_archive(archive_data)

    assert result["valid"] is True
    assert result["file_count"] == 4  # 4 files, 2 directories
    expected_size = sum(len(c) for c in entries.values())
    assert result["total_uncompressed_size"] == expected_size
    assert result["issues"] == []


# ---------------------------------------------------------------------------
# Malformed and Corrupted Inputs
# ---------------------------------------------------------------------------


def test_reject_empty_bytes():
    """Reject empty byte input."""
    result = validate_archive(b"")
    assert result["valid"] is False
    assert result["file_count"] == 0
    assert any("empty" in issue.lower() for issue in result["issues"])


@pytest.mark.parametrize("invalid_input", [None, 12345, "not-bytes-string", ["list"], {"dict": True}])
def test_reject_invalid_input_types(invalid_input):
    """Reject non-bytes input gracefully without exceptions."""
    result = validate_archive(invalid_input)  # type: ignore
    assert result["valid"] is False
    assert any("bytes" in issue.lower() for issue in result["issues"])


def test_reject_corrupted_zip_data():
    """Reject corrupted or random byte sequences that pretend to be ZIPs."""
    garbage = b"PK\x03\x04garbage_payload_that_is_not_a_valid_zip"
    result = validate_archive(garbage)

    assert result["valid"] is False
    assert any("malformed" in issue.lower() or "corrupt" in issue.lower() for issue in result["issues"])


def test_reject_empty_archive():
    """Reject a structurally valid ZIP that contains 0 entries."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        pass  # No entries written
    empty_zip = buf.getvalue()

    result = validate_archive(empty_zip)
    assert result["valid"] is False
    assert any("empty" in issue.lower() for issue in result["issues"])


def test_reject_archive_with_only_directories():
    """Reject an archive that contains directory entries but no actual files."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("empty_folder/", b"")
        zf.writestr("another_dir/", b"")
    dir_only_zip = buf.getvalue()

    result = validate_archive(dir_only_zip)
    assert result["valid"] is False
    assert result["file_count"] == 0
    assert any("no regular files" in issue.lower() for issue in result["issues"])


# ---------------------------------------------------------------------------
# Path Traversal & Unsafe Paths
# ---------------------------------------------------------------------------


def test_reject_path_traversal_dot_dot_prefix():
    """Reject ZIP entries attempting directory traversal via '../' prefix."""
    archive_data = _create_zip({"../escaped.py": b"malicious code"})
    result = validate_archive(archive_data)

    assert result["valid"] is False
    assert any("traversal" in issue.lower() for issue in result["issues"])


def test_reject_path_traversal_nested():
    """Reject ZIP entries attempting directory traversal within a subpath."""
    archive_data = _create_zip({"sub/../../evil.py": b"malicious code"})
    result = validate_archive(archive_data)

    assert result["valid"] is False
    assert any("traversal" in issue.lower() for issue in result["issues"])


def test_reject_path_traversal_backslash():
    """Reject ZIP entries attempting directory traversal with Windows backslashes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo(r"subdir\..\..\secret.txt")
        zf.writestr(info, b"traversal via backslash")
    archive_data = buf.getvalue()

    result = validate_archive(archive_data)
    assert result["valid"] is False
    assert any("traversal" in issue.lower() for issue in result["issues"])


def test_reject_absolute_path_unix():
    """Reject entries starting with a Unix absolute root '/'."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("/etc/passwd")
        zf.writestr(info, b"root:x:0:0")
    archive_data = buf.getvalue()

    result = validate_archive(archive_data)
    assert result["valid"] is False
    assert any("absolute" in issue.lower() for issue in result["issues"])


def test_reject_absolute_path_windows():
    """Reject entries starting with a Windows drive letter or backslash root."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info1 = zipfile.ZipInfo(r"C:\Windows\System32\calc.exe")
        zf.writestr(info1, b"bin")
    archive_data = buf.getvalue()

    result = validate_archive(archive_data)
    assert result["valid"] is False
    assert any("absolute" in issue.lower() for issue in result["issues"])


def test_reject_null_byte_in_filename():
    """Reject entry filenames containing null bytes or truncation tricks."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("innocent_txt_exe", b"null byte exploit")
    raw = bytearray(buf.getvalue())
    raw = raw.replace(b"innocent_txt_exe", b"innocent.txt\x00exe")
    archive_data = bytes(raw)

    result = validate_archive(archive_data)
    assert result["valid"] is False
    assert any("null byte" in issue.lower() or "truncation" in issue.lower() for issue in result["issues"])


def test_reject_excessive_path_length():
    """Reject entry paths exceeding the maximum character length."""
    long_name = "a/" * 260 + "toolong.py"  # > 500 chars
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(long_name, b"print(1)")
    archive_data = buf.getvalue()

    result = validate_archive(archive_data, max_path_length=DEFAULT_MAX_PATH_LENGTH)
    assert result["valid"] is False
    assert any("length" in issue.lower() for issue in result["issues"])


# ---------------------------------------------------------------------------
# Duplicate Paths
# ---------------------------------------------------------------------------


def test_reject_duplicate_paths():
    """Reject archives with exact duplicate file entries."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("common.py", b"version 1")
        zf.writestr("common.py", b"version 2")
    archive_data = buf.getvalue()

    result = validate_archive(archive_data)
    assert result["valid"] is False
    assert any("duplicate" in issue.lower() for issue in result["issues"])


def test_reject_duplicate_paths_slash_variation():
    """Reject archives with duplicate paths differing only by trailing or separator slash."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("src/module.py", b"first")
        zf.writestr(r"src\module.py", b"second")
    archive_data = buf.getvalue()

    result = validate_archive(archive_data)
    assert result["valid"] is False
    assert any("duplicate" in issue.lower() for issue in result["issues"])


def test_reject_duplicate_paths_case_insensitive():
    """Reject archives with duplicate paths that differ only by case (e.g. app.py vs APP.PY)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app.py", b"print('lowercase')")
        zf.writestr("APP.PY", b"print('uppercase')")
    archive_data = buf.getvalue()

    result = validate_archive(archive_data)
    assert result["valid"] is False
    assert any("duplicate" in issue.lower() and "case-insensitive" in issue.lower() for issue in result["issues"])


# ---------------------------------------------------------------------------
# Encrypted Entries & Symbolic Links
# ---------------------------------------------------------------------------


def test_reject_encrypted_entry():
    """Reject archives with encrypted or password-protected entries."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("secret.txt", b"secret-payload")
    raw = bytearray(buf.getvalue())
    # Set bit 0 (encryption flag) in central directory header (offset 8) and local file header (offset 6)
    idx_cd = raw.find(b"PK\x01\x02")
    if idx_cd != -1:
        raw[idx_cd + 8] |= 0x01
    idx_lf = raw.find(b"PK\x03\x04")
    if idx_lf != -1:
        raw[idx_lf + 6] |= 0x01
    archive_data = bytes(raw)

    result = validate_archive(archive_data)
    assert result["valid"] is False
    assert any("encrypted" in issue.lower() for issue in result["issues"])


def test_reject_symbolic_link():
    """Reject archives containing symbolic links."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("link_to_target")
        info.create_system = 3  # Unix
        info.external_attr = (stat.S_IFLNK | 0o777) << 16  # Symlink attribute
        zf.writestr(info, b"/etc/shadow")
    archive_data = buf.getvalue()

    result = validate_archive(archive_data)
    assert result["valid"] is False
    assert any("symbolic link" in issue.lower() for issue in result["issues"])


# ---------------------------------------------------------------------------
# Entry Limits & Oversized Files
# ---------------------------------------------------------------------------


def test_reject_excessive_entries():
    """Reject archives exceeding the maximum allowed entries count."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(10):
            zf.writestr(f"file_{i}.txt", b"x")
    archive_data = buf.getvalue()

    # Test with configurable max_entries=5
    result = validate_archive(archive_data, max_entries=5)
    assert result["valid"] is False
    assert any("entries limit" in issue.lower() for issue in result["issues"])


def test_reject_oversized_individual_file():
    """Reject archives containing a file larger than the configured max file size."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("large.bin", b"0" * 2000)
    archive_data = buf.getvalue()

    # Test with configurable max_file_size=1000
    result = validate_archive(archive_data, max_file_size=1000)
    assert result["valid"] is False
    assert any("maximum allowed size" in issue.lower() for issue in result["issues"])


def test_reject_excessive_total_uncompressed_size():
    """Reject archives whose combined uncompressed size exceeds max total size."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("file1.bin", b"A" * 600)
        zf.writestr("file2.bin", b"B" * 600)
    archive_data = buf.getvalue()

    # Test with configurable max_total_size=1000 (total is 1200)
    result = validate_archive(archive_data, max_total_size=1000)
    assert result["valid"] is False
    assert any("total uncompressed size" in issue.lower() for issue in result["issues"])


# ---------------------------------------------------------------------------
# Compression Ratio (Zip Bomb Protection)
# ---------------------------------------------------------------------------


def test_reject_suspicious_compression_ratio():
    """Reject archives with extreme compression ratios indicative of zip bombs."""
    # Highly repetitive bytes compress heavily under DEFLATE
    bomb_payload = b"0" * 300_000
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.bin", bomb_payload)
    archive_data = buf.getvalue()

    result = validate_archive(archive_data, max_compression_ratio=100.0)
    assert result["valid"] is False
    assert any("compression ratio" in issue.lower() for issue in result["issues"])


# ---------------------------------------------------------------------------
# Non-Extraction Assurance
# ---------------------------------------------------------------------------


def test_no_disk_extraction_occurs(tmp_path, monkeypatch):
    """Ensure validate_archive never writes or extracts files to disk."""
    monkeypatch.chdir(tmp_path)
    archive_data = _create_zip({
        "payload.py": b"print('should never touch disk')",
        "sub/module.py": b"x = 42",
    })

    result = validate_archive(archive_data)
    assert result["valid"] is True

    # Confirm tmp directory remained completely untouched
    assert list(tmp_path.iterdir()) == []
