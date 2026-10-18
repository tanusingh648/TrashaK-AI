"""Tests for TRASHAK AI Dependency and Project Health Analyzer."""

import io
import zipfile
import pytest

from backend.scanner.dependency_analyzer import analyze_dependencies


def _create_zip(entries: dict) -> bytes:
    """Helper to build an in-memory ZIP archive from a dict of {path: content_bytes}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, content in entries.items():
            zf.writestr(path, content)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Python Manifests (requirements.txt, pyproject.toml)
# ---------------------------------------------------------------------------


def test_python_requirements_txt():
    """Verify parsing of requirements.txt dependencies and matching imports."""
    reqs = b"""# Base dependencies
fastapi>=0.100.0
uvicorn[standard]
pydantic==2.0
-r other-requirements.txt  # Should be skipped cleanly
"""
    app_code = b"""import fastapi
import uvicorn
"""
    entries = {
        "requirements.txt": reqs,
        "app.py": app_code,
        "README.md": b"# My Project",
        "tests/test_app.py": b"def test_app(): pass",
        ".gitignore": b".venv/\n",
    }
    archive_data = _create_zip(entries)
    result = analyze_dependencies(archive_data)

    assert result["status"] == "success"
    assert result["validation"]["valid"] is True

    manifests = result["manifests"]
    assert len(manifests) == 1
    assert manifests[0]["manifest_type"] == "requirements.txt"
    assert manifests[0]["parsed"] is True

    dep_names = {d["name"] for d in result["dependencies"]}
    assert "fastapi" in dep_names
    assert "uvicorn" in dep_names
    assert "pydantic" in dep_names

    # fastapi and uvicorn are declared, so no undeclared dependency findings
    dep_gap_findings = [f for f in result["findings"] if f["category"] == "dependency_gap"]
    assert len(dep_gap_findings) == 0


def test_pyproject_toml():
    """Verify parsing of dependencies from pyproject.toml."""
    toml_content = b"""[project]
name = "trashak-sample"
version = "0.1.0"
dependencies = [
    "requests>=2.28",
    "click==8.1.3",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
]
"""
    entries = {
        "pyproject.toml": toml_content,
        "main.py": b"import click\ndef cli(): pass",
        "README.md": b"# Docs",
        "tests/test_cli.py": b"import pytest",
        ".gitignore": b".venv/",
    }
    archive_data = _create_zip(entries)
    result = analyze_dependencies(archive_data)

    assert result["status"] == "success"
    manifests = result["manifests"]
    assert len(manifests) == 1
    assert manifests[0]["manifest_type"] == "pyproject.toml"
    assert manifests[0]["parsed"] is True

    dep_names = {d["name"] for d in result["dependencies"]}
    assert "requests" in dep_names
    assert "click" in dep_names
    assert "pytest" in dep_names

    # Check dev dependency flag
    pytest_dep = next(d for d in result["dependencies"] if d["name"] == "pytest")
    assert pytest_dep["is_dev"] is True


# ---------------------------------------------------------------------------
# JavaScript Manifest (package.json)
# ---------------------------------------------------------------------------


def test_javascript_package_json():
    """Verify parsing of JavaScript package.json manifests and devDependencies."""
    pkg_json = b"""{
  "name": "frontend-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5"
  },
  "devDependencies": {
    "jest": "^29.5.0"
  }
}"""
    entries = {
        "package.json": pkg_json,
        "index.js": b"const express = require('express');",
        "README.md": b"# Frontend",
        ".gitignore": b"node_modules/",
        "tests/app.test.js": b"test('pass', () => {});",
    }
    archive_data = _create_zip(entries)
    result = analyze_dependencies(archive_data)

    assert result["status"] == "success"
    assert "javascript" in result["summary"]["ecosystems_detected"]

    manifests = result["manifests"]
    assert len(manifests) == 1
    assert manifests[0]["manifest_type"] == "package.json"

    deps = result["dependencies"]
    assert len(deps) == 3
    dep_map = {d["name"]: d for d in deps}

    assert "express" in dep_map and dep_map["express"]["is_dev"] is False
    assert "cors" in dep_map and dep_map["cors"]["is_dev"] is False
    assert "jest" in dep_map and dep_map["jest"]["is_dev"] is True


# ---------------------------------------------------------------------------
# Missing & Malformed Manifests
# ---------------------------------------------------------------------------


def test_missing_manifests():
    """Flag projects that contain source code but zero dependency manifests."""
    entries = {
        "main.py": b"import os\nprint('no manifest')",
        "README.md": b"# No Manifest Project",
        ".gitignore": b".venv/",
        "tests/test_main.py": b"def test_1(): pass",
    }
    archive_data = _create_zip(entries)
    result = analyze_dependencies(archive_data)

    assert result["status"] == "success"
    assert result["summary"]["manifests_discovered"] == 0

    manifest_findings = [f for f in result["findings"] if f["category"] == "manifest_gap"]
    assert len(manifest_findings) == 1
    assert manifest_findings[0]["severity"] == "warning"
    assert manifest_findings[0]["confidence"] == "confirmed"


def test_malformed_manifests():
    """Capture syntax errors in corrupted manifests without crashing."""
    corrupted_json = b"""{ "name": "bad-json", "dependencies": { "missing_quote: 123 }"""
    entries = {
        "package.json": corrupted_json,
        "README.md": b"# Broken manifest",
        ".gitignore": b"dist/",
    }
    archive_data = _create_zip(entries)
    result = analyze_dependencies(archive_data)

    assert result["status"] == "success"
    manifests = result["manifests"]
    assert len(manifests) == 1
    assert manifests[0]["parsed"] is False
    assert "JSON syntax error" in manifests[0]["error"]

    malformed_findings = [f for f in result["findings"] if f["category"] == "malformed_manifest"]
    assert len(malformed_findings) == 1
    assert malformed_findings[0]["severity"] == "error"
    assert malformed_findings[0]["confidence"] == "confirmed"


# ---------------------------------------------------------------------------
# Standard-Library & Local Module Import Protection
# ---------------------------------------------------------------------------


def test_standard_library_imports_not_flagged():
    """Verify that Python standard library imports are never flagged as undeclared."""
    code = b"""import sys
import os
import json
import math
from typing import List, Dict
import pathlib
import collections
"""
    entries = {
        "requirements.txt": b"fastapi\n",
        "script.py": code,
        "README.md": b"# Docs",
        ".gitignore": b".venv/",
        "tests/test_s.py": b"pass",
    }
    archive_data = _create_zip(entries)
    result = analyze_dependencies(archive_data)

    assert result["status"] == "success"
    gap_findings = [f for f in result["findings"] if f["category"] == "dependency_gap"]
    assert len(gap_findings) == 0


def test_local_module_imports_not_falsely_flagged():
    """Ensure local project modules and packages are not flagged as missing third-party packages."""
    entries = {
        "requirements.txt": b"fastapi\n",
        "my_project/__init__.py": b"",
        "my_project/utils.py": b"def helper(): return 42",
        "my_project/main.py": b"""from my_project.utils import helper
from .utils import helper
import my_project.utils
""",
        "README.md": b"# Local project",
        ".gitignore": b".venv/",
        "tests/test_pkg.py": b"pass",
    }
    archive_data = _create_zip(entries)
    result = analyze_dependencies(archive_data)

    assert result["status"] == "success"
    gap_findings = [f for f in result["findings"] if f["category"] == "dependency_gap"]
    assert len(gap_findings) == 0


# ---------------------------------------------------------------------------
# Undeclared Dependency Detection & Name Mapping
# ---------------------------------------------------------------------------


def test_declared_and_undeclared_dependencies():
    """Accurately identify undeclared third-party dependencies as uncertain warnings."""
    app_code = b"""import fastapi
import requests
import redis
"""
    entries = {
        "requirements.txt": b"fastapi==0.100.0\n",
        "app.py": app_code,
        "README.md": b"# App",
        ".gitignore": b".venv/",
        "tests/test_app.py": b"pass",
    }
    archive_data = _create_zip(entries)
    result = analyze_dependencies(archive_data)

    assert result["status"] == "success"
    gap_findings = [f for f in result["findings"] if f["category"] == "dependency_gap"]

    undeclared_mods = " ".join(f["description"] for f in gap_findings)
    assert "requests" in undeclared_mods
    assert "redis" in undeclared_mods
    assert "fastapi" not in undeclared_mods

    for finding in gap_findings:
        assert finding["severity"] == "warning"
        assert finding["confidence"] == "uncertain"


def test_import_name_mapping():
    """Recognize package distribution names that differ from import names (e.g. yaml -> pyyaml)."""
    app_code = b"""import yaml
from PIL import Image
"""
    entries = {
        "requirements.txt": b"PyYAML==6.0\nPillow==10.0.0\n",
        "app.py": app_code,
        "README.md": b"# Mapped",
        ".gitignore": b".venv/",
        "tests/test_app.py": b"pass",
    }
    archive_data = _create_zip(entries)
    result = analyze_dependencies(archive_data)

    assert result["status"] == "success"
    gap_findings = [f for f in result["findings"] if f["category"] == "dependency_gap"]
    assert len(gap_findings) == 0


# ---------------------------------------------------------------------------
# Project Health Warnings
# ---------------------------------------------------------------------------


def test_missing_readme_and_test_directory():
    """Detect health gaps when README, test directories, or .gitignore are absent."""
    entries = {
        "app.py": b"def run(): pass",
    }
    archive_data = _create_zip(entries)
    result = analyze_dependencies(archive_data)

    assert result["status"] == "success"
    categories = {f["category"] for f in result["findings"]}

    assert "documentation_gap" in categories
    assert "test_gap" in categories
    assert "configuration_gap" in categories


# ---------------------------------------------------------------------------
# Error Handling & Validation
# ---------------------------------------------------------------------------


def test_invalid_zip_and_unsafe_archive_rejection():
    """Reject corrupted byte inputs and traversal attacks before analysis."""
    bad_result = analyze_dependencies(b"garbage-not-a-zip")
    assert bad_result["status"] == "error"
    assert bad_result["validation"]["valid"] is False
    assert bad_result["manifests"] == []

    unsafe_data = _create_zip({"../evil.py": b"code"})
    unsafe_result = analyze_dependencies(unsafe_data)
    assert unsafe_result["status"] == "error"
    assert unsafe_result["validation"]["valid"] is False
    assert any("traversal" in issue.lower() for issue in unsafe_result["issues"])


def test_empty_valid_archive():
    """Reject empty ZIP archives cleanly."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        pass
    empty_zip = buf.getvalue()

    result = analyze_dependencies(empty_zip)
    assert result["status"] == "error"
    assert result["validation"]["valid"] is False
    assert result["manifests"] == []
    assert result["summary"]["manifests_discovered"] == 0


def test_accurate_summary_counts():
    """Ensure aggregate metric counters are computed accurately."""
    entries = {
        "requirements.txt": b"fastapi\nuvicorn\n",
        "pyproject.toml": b"[project]\nname='sample'\ndependencies=['pydantic']\n",
        "main.py": b"import fastapi\nimport requests",
        "README.md": b"# Docs",
        ".gitignore": b".venv/",
        "tests/test_main.py": b"pass",
    }
    archive_data = _create_zip(entries)
    result = analyze_dependencies(archive_data)

    assert result["status"] == "success"
    summary = result["summary"]

    assert summary["manifests_discovered"] == 2
    assert summary["dependencies_declared"] == 3  # fastapi, uvicorn, pydantic
    assert summary["import_comparisons_performed"] >= 2
    assert summary["health_findings_count"] == len(result["findings"])
    assert "python" in summary["ecosystems_detected"]
