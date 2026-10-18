"""TRASHAK AI - Project File Inventory Scanner.

Analyzes the structure and contents of a validated ZIP archive without
extracting files to disk or executing any uploaded content.
Classifies software assets, counts metrics, and filters vendor/generated directories.
"""

import io
import os
import re
import zipfile
from typing import Any, Dict, List, Set

from backend.core.archive_validator import validate_archive

# Canonical asset classification categories
CATEGORIES = (
    "source_code",
    "documentation",
    "configuration",
    "test",
    "data",
    "other",
)

# Common generated or vendor directories to ignore during inventory
IGNORED_DIRECTORIES: Set[str] = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".pytest_cache",
}

# Source code extensions
SOURCE_CODE_EXTENSIONS: Set[str] = {
    ".py",
    ".pyw",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".mts",
    ".cts",
    ".jsx",
    ".tsx",
    ".java",
    ".cpp",
    ".c",
    ".cc",
    ".cxx",
    ".h",
    ".hpp",
    ".hh",
    ".hxx",
    ".cs",
    ".go",
    ".rs",
    ".php",
    ".rb",
    ".html",
    ".htm",
    ".css",
    ".scss",
    ".sass",
    ".less",
    ".sql",
    ".sh",
    ".bash",
    ".zsh",
    ".swift",
    ".kt",
    ".kts",
    ".scala",
    ".dart",
    ".lua",
    ".pl",
    ".pm",
}

# Documentation extensions and standalone filenames
DOCUMENTATION_EXTENSIONS: Set[str] = {
    ".md",
    ".markdown",
    ".rst",
    ".txt",
    ".pdf",
    ".adoc",
    ".asciidoc",
}

DOCUMENTATION_FILENAMES: Set[str] = {
    "readme",
    "license",
    "licence",
    "changelog",
    "contributing",
    "authors",
    "notice",
    "copying",
    "code_of_conduct",
    "roadmap",
    "architecture",
}

# Configuration extensions and recognized filenames
CONFIGURATION_EXTENSIONS: Set[str] = {
    ".toml",
    ".ini",
    ".cfg",
    ".yaml",
    ".yml",
    ".env.example",
    ".conf",
}

CONFIGURATION_FILENAMES: Set[str] = {
    "dockerfile",
    "makefile",
    "gnumakefile",
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "setup.py",
    "setup.cfg",
    "pipfile",
    "pipfile.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "cargo.toml",
    "cargo.lock",
    "composer.json",
    "composer.lock",
    "gemfile",
    "gemfile.lock",
    "go.mod",
    "go.sum",
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.defaults",
    ".gitignore",
    ".gitattributes",
    ".dockerignore",
    ".editorconfig",
    "tsconfig.json",
    "jsconfig.json",
}

# Data file extensions
DATA_EXTENSIONS: Set[str] = {
    ".json",
    ".xml",
    ".csv",
    ".tsv",
    ".parquet",
    ".feather",
    ".avro",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".dat",
}


def classify_file(norm_path: str) -> str:
    """Classify a relative file path into one of the 6 canonical categories.

    Test classification takes precedence over ordinary source-code classification.
    """
    parts = [p.lower() for p in norm_path.split("/") if p]
    if not parts:
        return "other"

    filename = parts[-1]
    fname_lower = filename.lower()
    dir_parts = parts[:-1]

    # 1. Configuration check by specific filename pattern
    if fname_lower in CONFIGURATION_FILENAMES:
        return "configuration"
    if fname_lower.startswith("requirements") and fname_lower.endswith(".txt"):
        return "configuration"
    if fname_lower.startswith("dockerfile"):
        return "configuration"
    if fname_lower.endswith(".env.example"):
        return "configuration"
    if any(fname_lower.endswith(lock) for lock in [".lock", "-lock.json", "-lock.yaml"]):
        return "configuration"
    if fname_lower.endswith(("rc", "rc.json", "rc.js", "rc.yml", "rc.yaml")):
        return "configuration"

    # 2. Test identification (takes precedence over source code)
    is_test_dir = any(p in {"tests", "test", "__tests__", "spec", "specs"} for p in dir_parts)
    is_test_name = (
        fname_lower.startswith(("test_", "test-"))
        or bool(re.search(r"(\.|_|-)(test|spec)\.[a-zA-Z0-9]+$", fname_lower))
        or fname_lower in {"conftest.py", "test.py", "test.js", "test.ts"}
    )

    _, ext = os.path.splitext(fname_lower)

    if is_test_name:
        return "test"
    if is_test_dir and (ext in SOURCE_CODE_EXTENSIONS or is_test_name):
        return "test"

    # 3. Configuration check by extension
    if ext in CONFIGURATION_EXTENSIONS:
        return "configuration"

    # 4. Documentation check
    base_name = os.path.splitext(fname_lower)[0]
    if base_name in DOCUMENTATION_FILENAMES or fname_lower in DOCUMENTATION_FILENAMES:
        return "documentation"
    if ext in DOCUMENTATION_EXTENSIONS:
        return "documentation"

    # 5. Source code check
    if ext in SOURCE_CODE_EXTENSIONS:
        return "source_code"

    # 6. Data check
    if ext in DATA_EXTENSIONS:
        return "data"

    return "other"


def build_inventory(data: bytes) -> Dict[str, Any]:
    """Scan and catalog the file structure of a software project ZIP archive.

    Reuses validate_archive. If validation fails, no inventory is performed
    and a structured failure response is returned.

    Never extracts files to disk or executes archive contents.

    Args:
        data: Raw archive bytes.

    Returns:
        Dict containing:
            - status (str): "success" or "error"
            - validation (dict): validation report from validate_archive
            - summary (dict): total_files, total_size_bytes, and counts_by_category
            - files (list[dict]): list of file records
            - ignored_entries (int): number of ignored entries in vendor/generated dirs
    """
    # 1. Validate the archive first
    validation = validate_archive(data)

    empty_summary = {
        "total_files": 0,
        "total_size_bytes": 0,
        "counts_by_category": {cat: 0 for cat in CATEGORIES},
    }

    if not validation["valid"]:
        return {
            "status": "error",
            "validation": validation,
            "summary": empty_summary,
            "files": [],
            "ignored_entries": 0,
        }

    # 2. Process valid archive in-memory
    files: List[Dict[str, Any]] = []
    ignored_entries = 0
    total_size_bytes = 0
    counts_by_category: Dict[str, int] = {cat: 0 for cat in CATEGORIES}

    try:
        archive_buffer = io.BytesIO(data)
        with zipfile.ZipFile(archive_buffer, "r") as zf:
            for info in zf.infolist():
                raw_filename = info.filename
                norm_path = raw_filename.replace("\\", "/").strip("/")

                if not norm_path:
                    continue

                parts = norm_path.split("/")
                is_dir = (
                    info.is_dir()
                    or raw_filename.endswith("/")
                    or raw_filename.endswith("\\")
                )

                # Check if entry is inside an ignored vendor/generated directory
                dir_components = parts if is_dir else parts[:-1]
                if any(comp.lower() in IGNORED_DIRECTORIES for comp in dir_components):
                    ignored_entries += 1
                    continue

                # Directory entries outside ignored paths are not counted as files
                if is_dir:
                    continue

                # Process regular file
                filename = parts[-1]
                fname_lower = filename.lower()
                if fname_lower.endswith(".env.example"):
                    extension = ".env.example"
                else:
                    _, ext = os.path.splitext(filename)
                    extension = ext.lower()

                category = classify_file(norm_path)
                counts_by_category[category] += 1
                total_size_bytes += info.file_size

                files.append(
                    {
                        "path": norm_path,
                        "name": filename,
                        "extension": extension,
                        "size_bytes": info.file_size,
                        "category": category,
                    }
                )

    except Exception as exc:
        return {
            "status": "error",
            "validation": {
                "valid": False,
                "file_count": 0,
                "total_uncompressed_size": 0,
                "issues": [f"Failed to scan archive inventory: {type(exc).__name__}"],
            },
            "summary": empty_summary,
            "files": [],
            "ignored_entries": 0,
        }

    summary = {
        "total_files": len(files),
        "total_size_bytes": total_size_bytes,
        "counts_by_category": counts_by_category,
    }

    return {
        "status": "success",
        "validation": validation,
        "summary": summary,
        "files": files,
        "ignored_entries": ignored_entries,
    }
