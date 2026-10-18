"""Tests for TRASHAK AI Project File Inventory Scanner."""

import io
import zipfile
import pytest

from backend.core.file_inventory import build_inventory, classify_file


def _create_zip(entries: dict) -> bytes:
    """Helper to build an in-memory ZIP archive from a dict of {path: content_bytes}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, content in entries.items():
            zf.writestr(path, content)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Classification Logic Unit Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,expected_category",
    [
        ("main.py", "source_code"),
        ("src/app.js", "source_code"),
        ("src/index.ts", "source_code"),
        ("src/component.jsx", "source_code"),
        ("src/widget.tsx", "source_code"),
        ("server/App.java", "source_code"),
        ("core/engine.cpp", "source_code"),
        ("core/native.c", "source_code"),
        ("core/native.h", "source_code"),
        ("service/Program.cs", "source_code"),
        ("api/main.go", "source_code"),
        ("src/lib.rs", "source_code"),
        ("index.php", "source_code"),
        ("app.rb", "source_code"),
        ("public/index.html", "source_code"),
        ("static/style.css", "source_code"),
        ("db/schema.sql", "source_code"),
        ("README.md", "documentation"),
        ("docs/guide.rst", "documentation"),
        ("notes.txt", "documentation"),
        ("manual.pdf", "documentation"),
        ("LICENSE", "documentation"),
        ("CHANGELOG", "documentation"),
        ("Dockerfile", "configuration"),
        ("Dockerfile.dev", "configuration"),
        ("Makefile", "configuration"),
        ("requirements.txt", "configuration"),
        ("requirements-dev.txt", "configuration"),
        ("pyproject.toml", "configuration"),
        ("package.json", "configuration"),
        ("package-lock.json", "configuration"),
        ("yarn.lock", "configuration"),
        (".env.example", "configuration"),
        ("config.yaml", "configuration"),
        ("settings.ini", "configuration"),
        ("setup.cfg", "configuration"),
        ("tests/test_api.py", "test"),
        ("test/unit_test.py", "test"),
        ("src/calc.test.js", "test"),
        ("src/calc.spec.ts", "test"),
        ("test_something.py", "test"),
        ("tests/conftest.py", "test"),
        ("data/records.json", "data"),
        ("feed.xml", "data"),
        ("dataset.csv", "data"),
        ("metrics.tsv", "data"),
        ("logo.png", "other"),
        ("font.woff2", "other"),
    ],
)
def test_classify_file(path: str, expected_category: str):
    """Ensure various paths and extensions are classified correctly."""
    assert classify_file(path) == expected_category


# ---------------------------------------------------------------------------
# Mixed File Types
# ---------------------------------------------------------------------------


def test_mixed_file_types():
    """Verify inventory scanning on an archive containing mixed asset categories."""
    entries = {
        "src/main.py": b"print('app')",
        "src/app.js": b"console.log('web')",
        "README.md": b"# Docs",
        "requirements.txt": b"fastapi\nuvicorn\n",
        "Dockerfile": b"FROM python:3.10\n",
        "tests/test_main.py": b"def test_pass(): assert True",
        "data/sample.json": b'{"key": "value"}',
        "assets/logo.png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
    }
    archive_data = _create_zip(entries)
    result = build_inventory(archive_data)

    assert result["status"] == "success"
    assert result["validation"]["valid"] is True

    summary = result["summary"]
    assert summary["total_files"] == 8
    assert summary["counts_by_category"]["source_code"] == 2
    assert summary["counts_by_category"]["documentation"] == 1
    assert summary["counts_by_category"]["configuration"] == 2
    assert summary["counts_by_category"]["test"] == 1
    assert summary["counts_by_category"]["data"] == 1
    assert summary["counts_by_category"]["other"] == 1

    file_paths = {f["path"] for f in result["files"]}
    assert file_paths == set(entries.keys())

    # Check file record structure
    for rec in result["files"]:
        assert "path" in rec
        assert "name" in rec
        assert "extension" in rec
        assert "size_bytes" in rec
        assert "category" in rec
        assert rec["size_bytes"] == len(entries[rec["path"]])


# ---------------------------------------------------------------------------
# Empty and Invalid Inputs
# ---------------------------------------------------------------------------


def test_empty_valid_zip():
    """Empty ZIP archives must be rejected by validation with no inventory created."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        pass
    empty_zip = buf.getvalue()

    result = build_inventory(empty_zip)
    assert result["status"] == "error"
    assert result["validation"]["valid"] is False
    assert any("empty" in issue.lower() for issue in result["validation"]["issues"])
    assert result["files"] == []
    assert result["summary"]["total_files"] == 0
    assert result["ignored_entries"] == 0


def test_invalid_zip_input():
    """Invalid byte sequences must fail cleanly without tracebacks."""
    result = build_inventory(b"corrupted-not-a-zip-payload")
    assert result["status"] == "error"
    assert result["validation"]["valid"] is False
    assert result["files"] == []
    assert result["summary"]["total_files"] == 0


def test_unsafe_archive_rejection():
    """Unsafe archives (traversal, absolute path) must be rejected before inventorying."""
    archive_data = _create_zip({"../escaped.py": b"malicious traversal code"})
    result = build_inventory(archive_data)

    assert result["status"] == "error"
    assert result["validation"]["valid"] is False
    assert any("traversal" in issue.lower() for issue in result["validation"]["issues"])
    assert result["files"] == []
    assert result["summary"]["total_files"] == 0


# ---------------------------------------------------------------------------
# Test Classification Precedence
# ---------------------------------------------------------------------------


def test_test_file_classification_precedence():
    """Ensure test files are classified as 'test' rather than 'source_code'."""
    entries = {
        "tests/test_api.py": b"def test_1(): pass",
        "tests/helpers.py": b"def mock_client(): pass",
        "src/utils.test.js": b"test('add', () => {})",
        "src/calc.spec.ts": b"describe('calc', () => {})",
        "test_cli.py": b"def test_run(): pass",
        "src/normal_module.py": b"def compute(): return 1",
    }
    archive_data = _create_zip(entries)
    result = build_inventory(archive_data)

    assert result["status"] == "success"
    by_path = {f["path"]: f["category"] for f in result["files"]}

    assert by_path["tests/test_api.py"] == "test"
    assert by_path["tests/helpers.py"] == "test"
    assert by_path["src/utils.test.js"] == "test"
    assert by_path["src/calc.spec.ts"] == "test"
    assert by_path["test_cli.py"] == "test"
    assert by_path["src/normal_module.py"] == "source_code"

    assert result["summary"]["counts_by_category"]["test"] == 5
    assert result["summary"]["counts_by_category"]["source_code"] == 1


# ---------------------------------------------------------------------------
# Ignored Directories
# ---------------------------------------------------------------------------


def test_ignored_directories():
    """Verify vendor, cache, and build directories are filtered and counted as ignored."""
    entries = {
        "src/index.py": b"print(1)",
        "node_modules/lodash/index.js": b"module.exports = {}",
        "node_modules/lodash/package.json": b'{"name": "lodash"}',
        ".venv/lib/site-packages/pkg.py": b"# venv pkg",
        "venv/bin/activate": b"# activate script",
        ".git/config": b"[core]\nrepositoryformatversion = 0",
        ".git/HEAD": b"ref: refs/heads/main",
        "__pycache__/index.cpython-310.pyc": b"\x00\x00\x00\x00",
        "dist/bundle.js": b"var bundled = true;",
        "build/output.bin": b"\x01\x02\x03",
        ".pytest_cache/cache.json": b"{}",
    }
    archive_data = _create_zip(entries)
    result = build_inventory(archive_data)

    assert result["status"] == "success"
    assert result["summary"]["total_files"] == 1
    assert result["files"][0]["path"] == "src/index.py"
    assert result["ignored_entries"] == 10


# ---------------------------------------------------------------------------
# Requirements and Dockerfile Classification
# ---------------------------------------------------------------------------


def test_requirements_and_dockerfile_classification():
    """Ensure build, dependency, and configuration manifests are categorized as configuration."""
    entries = {
        "requirements.txt": b"fastapi==0.100.0",
        "requirements-dev.txt": b"pytest==8.0.0",
        "Dockerfile": b"FROM python:3.10-slim",
        "Dockerfile.production": b"FROM node:18-alpine",
        "pyproject.toml": b"[project]\nname = 'trashak'",
        "package.json": b'{"name": "trashak"}',
        "package-lock.json": b'{"name": "trashak", "lockfileVersion": 3}',
        ".env.example": b"API_KEY=your_key_here",
    }
    archive_data = _create_zip(entries)
    result = build_inventory(archive_data)

    assert result["status"] == "success"
    assert result["summary"]["total_files"] == 8
    assert result["summary"]["counts_by_category"]["configuration"] == 8

    for f in result["files"]:
        assert f["category"] == "configuration"


# ---------------------------------------------------------------------------
# Accurate Counts and Sizes
# ---------------------------------------------------------------------------


def test_accurate_file_counts_and_sizes():
    """Ensure accurate tracking of individual and total sizes and category counts."""
    file_a = b"A" * 150
    file_b = b"B" * 250
    file_c = b"C" * 350
    entries = {
        "src/a.py": file_a,
        "docs/b.md": file_b,
        "data/c.json": file_c,
    }
    archive_data = _create_zip(entries)
    result = build_inventory(archive_data)

    assert result["status"] == "success"
    summary = result["summary"]
    assert summary["total_files"] == 3
    assert summary["total_size_bytes"] == 750

    assert summary["counts_by_category"]["source_code"] == 1
    assert summary["counts_by_category"]["documentation"] == 1
    assert summary["counts_by_category"]["data"] == 1
    assert summary["counts_by_category"]["configuration"] == 0
    assert summary["counts_by_category"]["test"] == 0
    assert summary["counts_by_category"]["other"] == 0

    assert sum(f["size_bytes"] for f in result["files"]) == 750


# ---------------------------------------------------------------------------
# Non-Extraction Assurance
# ---------------------------------------------------------------------------


def test_build_inventory_no_disk_extraction(tmp_path, monkeypatch):
    """Ensure build_inventory operates strictly in-memory without touching disk."""
    monkeypatch.chdir(tmp_path)
    entries = {
        "src/main.py": b"print('in memory')",
        "config.json": b"{}",
    }
    archive_data = _create_zip(entries)
    result = build_inventory(archive_data)

    assert result["status"] == "success"
    assert list(tmp_path.iterdir()) == []
