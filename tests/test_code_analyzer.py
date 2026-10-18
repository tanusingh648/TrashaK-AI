"""Tests for TRASHAK AI Python Code Structure Analyzer."""

import io
import zipfile
import pytest

from backend.scanner.code_analyzer import analyze_python_code


def _create_zip(entries: dict) -> bytes:
    """Helper to build an in-memory ZIP archive from a dict of {path: content_bytes}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, content in entries.items():
            zf.writestr(path, content)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Functions and Classes Extraction
# ---------------------------------------------------------------------------


def test_valid_python_file_functions_and_classes():
    """Ensure functions, async functions, classes, and methods are extracted accurately."""
    code = b'''"""Sample module docstring."""

def regular_func(x: int) -> int:
    return x * 2

async def fetch_data(url: str):
    return {"status": "ok"}

class BaseService:
    def __init__(self, name: str):
        self.name = name

class UserService(BaseService):
    def get_user(self, user_id: int):
        return {"id": user_id}

    async def update_user(self, user_id: int, data: dict):
        return True
'''
    archive_data = _create_zip({"services/user.py": code})
    result = analyze_python_code(archive_data)

    assert result["status"] == "success"
    assert result["validation"]["valid"] is True
    assert result["summary"]["total_python_files"] == 1
    assert result["summary"]["parsed_files"] == 1
    assert result["summary"]["syntax_error_files"] == 0

    file_record = result["files"][0]
    assert file_record["path"] == "services/user.py"
    assert file_record["parsed"] is True
    assert file_record["syntax_error"] is None
    assert file_record["line_count"] > 15

    # Check function names
    func_names = [f["name"] for f in file_record["functions"]]
    assert "regular_func" in func_names
    assert "fetch_data" in func_names
    assert "__init__" in func_names
    assert "get_user" in func_names
    assert "update_user" in func_names

    # Check async detection
    async_funcs = [f["name"] for f in file_record["functions"] if f["is_async"]]
    assert "fetch_data" in async_funcs
    assert "update_user" in async_funcs

    # Check classes
    assert len(file_record["classes"]) == 2
    class_map = {c["name"]: c for c in file_record["classes"]}
    assert "BaseService" in class_map
    assert "UserService" in class_map
    assert "BaseService" in class_map["UserService"]["bases"]

    user_methods = [m["name"] for m in class_map["UserService"]["methods"]]
    assert "get_user" in user_methods
    assert "update_user" in user_methods


# ---------------------------------------------------------------------------
# Import Extraction
# ---------------------------------------------------------------------------


def test_import_extraction():
    """Verify regular imports, from-imports, aliases, and line numbers."""
    code = b'''import sys
import os, json
from typing import List, Dict as D
from math import sqrt
'''
    archive_data = _create_zip({"importer.py": code})
    result = analyze_python_code(archive_data)

    assert result["status"] == "success"
    file_record = result["files"][0]
    imports = file_record["imports"]

    assert len(imports) == 6  # sys, os, json, List, Dict as D, sqrt

    import_names = {(i["module"], i["name"], i["alias"], i["is_from"]) for i in imports}
    assert ("sys", "sys", None, False) in import_names
    assert ("os", "os", None, False) in import_names
    assert ("json", "json", None, False) in import_names
    assert ("typing", "List", None, True) in import_names
    assert ("typing", "Dict", "D", True) in import_names
    assert ("math", "sqrt", None, True) in import_names


# ---------------------------------------------------------------------------
# Main-Guard and Entry-Point Detection
# ---------------------------------------------------------------------------


def test_main_guard_detection():
    """Verify detection of if __name__ == '__main__': entry guards and filenames."""
    main_code = b'''def run():
    print("running")

if __name__ == "__main__":
    run()
'''
    lib_code = b'''def helper():
    return 42
'''
    alt_guard_code = b'''if "__main__" == __name__:
    print("alt guard")
'''
    archive_data = _create_zip({
        "app.py": main_code,
        "utils.py": lib_code,
        "worker.py": alt_guard_code,
    })
    result = analyze_python_code(archive_data)

    assert result["status"] == "success"
    by_path = {f["path"]: f for f in result["files"]}

    assert by_path["app.py"]["has_main_guard"] is True
    assert "if __name__ == '__main__'" in by_path["app.py"]["entry_point_indicators"]
    assert "filename: app.py" in by_path["app.py"]["entry_point_indicators"]

    assert by_path["utils.py"]["has_main_guard"] is False
    assert by_path["utils.py"]["entry_point_indicators"] == []

    assert by_path["worker.py"]["has_main_guard"] is True
    assert "if __name__ == '__main__'" in by_path["worker.py"]["entry_point_indicators"]

    assert "app.py" in result["summary"]["entry_point_candidates"]
    assert "worker.py" in result["summary"]["entry_point_candidates"]
    assert "utils.py" not in result["summary"]["entry_point_candidates"]


# ---------------------------------------------------------------------------
# Multiple Python Files
# ---------------------------------------------------------------------------


def test_multiple_python_files():
    """Ensure analysis scans across multiple directories and aggregates metrics."""
    entries = {
        "backend/main.py": b"import os\ndef start(): pass",
        "backend/core/config.py": b"DEBUG = True",
        "backend/scanner/parser.py": b"def parse(): pass",
        "README.md": b"# Non-python file",
    }
    archive_data = _create_zip(entries)
    result = analyze_python_code(archive_data)

    assert result["status"] == "success"
    assert result["summary"]["total_python_files"] == 3
    assert result["summary"]["parsed_files"] == 3
    analyzed_paths = {f["path"] for f in result["files"]}
    assert analyzed_paths == {"backend/main.py", "backend/core/config.py", "backend/scanner/parser.py"}


# ---------------------------------------------------------------------------
# Syntax Errors
# ---------------------------------------------------------------------------


def test_syntax_errors():
    """Ensure files with syntax errors are captured gracefully without crashing."""
    broken_code = b'''def broken_function(
    print("missing closing paren and colon"
'''
    valid_code = b'''def good(): return 1'''

    archive_data = _create_zip({
        "bad.py": broken_code,
        "good.py": valid_code,
    })
    result = analyze_python_code(archive_data)

    assert result["status"] == "success"
    assert result["summary"]["total_python_files"] == 2
    assert result["summary"]["parsed_files"] == 1
    assert result["summary"]["syntax_error_files"] == 1

    by_path = {f["path"]: f for f in result["files"]}
    assert by_path["bad.py"]["parsed"] is False
    assert "SyntaxError" in by_path["bad.py"]["syntax_error"]

    assert by_path["good.py"]["parsed"] is True
    assert by_path["good.py"]["syntax_error"] is None

    syntax_findings = [f for f in result["findings"] if f["type"] == "syntax_error"]
    assert len(syntax_findings) == 1
    assert syntax_findings[0]["path"] == "bad.py"


# ---------------------------------------------------------------------------
# Invalid and Unsafe Archives
# ---------------------------------------------------------------------------


def test_invalid_zip_input():
    """Ensure invalid byte payloads are rejected cleanly."""
    result = analyze_python_code(b"corrupted-not-a-zip")
    assert result["status"] == "error"
    assert result["validation"]["valid"] is False
    assert result["files"] == []
    assert result["summary"]["total_python_files"] == 0


def test_unsafe_zip_rejection():
    """Ensure unsafe archives with path traversal are rejected before AST parsing."""
    archive_data = _create_zip({"../evil.py": b"import os"})
    result = analyze_python_code(archive_data)

    assert result["status"] == "error"
    assert result["validation"]["valid"] is False
    assert any("traversal" in issue.lower() for issue in result["issues"])
    assert result["files"] == []


def test_empty_valid_zip():
    """Ensure empty valid ZIP is rejected by validator."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        pass
    empty_zip = buf.getvalue()

    result = analyze_python_code(empty_zip)
    assert result["status"] == "error"
    assert result["validation"]["valid"] is False
    assert result["files"] == []
    assert result["summary"]["total_python_files"] == 0


# ---------------------------------------------------------------------------
# Relative Imports
# ---------------------------------------------------------------------------


def test_relative_imports():
    """Verify resolution of relative imports when matching local modules exist."""
    entries = {
        "pkg/__init__.py": b"",
        "pkg/utils.py": b"def helper(): pass",
        "pkg/module.py": b"from .utils import helper\nfrom . import utils",
    }
    archive_data = _create_zip(entries)
    result = analyze_python_code(archive_data)

    assert result["status"] == "success"
    by_path = {f["path"]: f for f in result["files"]}

    mod_imports = by_path["pkg/module.py"]["imports"]
    assert any(i["is_relative"] and i["module"] == "utils" and i["level"] == 1 for i in mod_imports)

    # When target local files exist, no unresolved local import finding should be generated
    unresolved = [f for f in result["findings"] if f["type"] == "possible_unresolved_local_import"]
    assert len(unresolved) == 0


# ---------------------------------------------------------------------------
# Likely Missing Local Import Detection
# ---------------------------------------------------------------------------


def test_likely_missing_local_import():
    """Verify detection of missing local modules for relative and project-local imports."""
    entries = {
        "backend/__init__.py": b"",
        "backend/main.py": b'''
import sys
import fastapi
from .non_existent_module import missing_func
from backend.services.missing_service import process_data
''',
    }
    archive_data = _create_zip(entries)
    result = analyze_python_code(archive_data)

    assert result["status"] == "success"

    unresolved = [f for f in result["findings"] if f["type"] == "possible_unresolved_local_import"]
    assert len(unresolved) == 2

    messages = " ".join(f["message"] for f in unresolved)
    assert "non_existent_module" in messages
    assert "backend.services.missing_service" in messages

    # Standard library and third-party imports must NOT be marked as unresolved local imports
    assert "sys" not in messages
    assert "fastapi" not in messages


# ---------------------------------------------------------------------------
# Summary Counts
# ---------------------------------------------------------------------------


def test_correct_summary_counts():
    """Ensure summary metrics accurately reflect function, class, import, and file totals."""
    file1 = b'''import math
from os import path

def func_a(): pass
def func_b(): pass

class Calculator:
    def add(self, a, b): return a + b
    def sub(self, a, b): return a - b
'''
    file2 = b'''import sys

def run(): pass

if __name__ == "__main__":
    run()
'''
    file3 = b'''def broken(:'''

    entries = {
        "math_utils.py": file1,
        "main.py": file2,
        "broken.py": file3,
    }
    archive_data = _create_zip(entries)
    result = analyze_python_code(archive_data)

    assert result["status"] == "success"
    summary = result["summary"]

    assert summary["total_python_files"] == 3
    assert summary["parsed_files"] == 2
    assert summary["syntax_error_files"] == 1

    # file1: func_a, func_b, Calculator.add, Calculator.sub (4 functions)
    # file2: run (1 function)
    # Total = 5 functions
    assert summary["function_count"] == 5

    # file1: Calculator (1 class)
    assert summary["class_count"] == 1

    # file1: math, path (2 imports)
    # file2: sys (1 import)
    # Total = 3 imports
    assert summary["import_count"] == 3

    assert "main.py" in summary["entry_point_candidates"]


# ---------------------------------------------------------------------------
# Vendor Directories Ignored & Non-Extraction
# ---------------------------------------------------------------------------


def test_vendor_directories_ignored():
    """Ensure Python files in vendor or build directories are excluded from analysis."""
    entries = {
        "src/app.py": b"def start(): pass",
        ".venv/lib/site-packages/pkg.py": b"def venv_func(): pass",
        "node_modules/pkg/setup.py": b"def node_func(): pass",
        "__pycache__/app.cpython-310.py": b"def cache_func(): pass",
    }
    archive_data = _create_zip(entries)
    result = analyze_python_code(archive_data)

    assert result["status"] == "success"
    assert result["summary"]["total_python_files"] == 1
    assert result["files"][0]["path"] == "src/app.py"


def test_no_disk_extraction(tmp_path, monkeypatch):
    """Ensure analyze_python_code operates strictly in-memory without disk extraction."""
    monkeypatch.chdir(tmp_path)
    entries = {
        "app.py": b"def run(): pass",
        "core.py": b"class Engine: pass",
    }
    archive_data = _create_zip(entries)
    result = analyze_python_code(archive_data)

    assert result["status"] == "success"
    assert list(tmp_path.iterdir()) == []
