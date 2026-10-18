"""TRASHAK AI - Python Code Structure Analyzer.

Extracts structural evidence from Python source files in a validated ZIP archive
without extracting files to disk or executing uploaded code.
Identifies functions, classes, imports, entry points, syntax errors, and
potential unresolved local imports using Python's standard-library AST.
"""

import ast
import io
import os
import sys
import zipfile
from typing import Any, Dict, List, Optional, Set

from backend.core.archive_validator import validate_archive

# Common vendor or generated directories to exclude from analysis
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

# Standard library module names in Python 3.10+
STDLIB_MODULES: Set[str] = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else set()


def _check_main_guard(tree: ast.AST) -> bool:
    """Check if an AST contains an `if __name__ == '__main__':` pattern."""
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            test = node.test
            if isinstance(test, ast.Compare):
                left = test.left
                for op, comp in zip(test.ops, test.comparators):
                    if isinstance(op, ast.Eq):
                        # __name__ == '__main__'
                        if (
                            isinstance(left, ast.Name)
                            and left.id == "__name__"
                            and isinstance(comp, ast.Constant)
                            and comp.value == "__main__"
                        ):
                            return True
                        # '__main__' == __name__
                        if (
                            isinstance(left, ast.Constant)
                            and left.value == "__main__"
                            and isinstance(comp, ast.Name)
                            and comp.id == "__name__"
                        ):
                            return True
    return False


def _check_unresolved_local_imports(
    python_files_data: List[Dict[str, Any]],
    all_project_files: Set[str],
) -> List[Dict[str, Any]]:
    """Identify potential unresolved local imports using project file topology.

    Never flags standard library or third-party packages as missing local modules
    without explicit evidence from the project's directory structure or relative imports.
    """
    unresolved_findings: List[Dict[str, Any]] = []

    # Map of all python files normalized
    py_files_set = {p for p in all_project_files if p.endswith((".py", ".pyw"))}

    # Discover top-level local package root names in the archive
    # (directories containing python files or __init__.py, or root .py files)
    local_roots: Set[str] = set()
    for p in py_files_set:
        parts = p.split("/")
        if len(parts) > 1:
            local_roots.add(parts[0].lower())
        else:
            base_name = os.path.splitext(parts[0])[0].lower()
            local_roots.add(base_name)

    for file_info in python_files_data:
        file_path = file_info["path"]
        file_dir_parts = file_path.split("/")[:-1]

        for imp in file_info["imports"]:
            is_relative = imp["is_relative"]
            level = imp["level"]
            module = imp["module"]
            name = imp["name"]
            line = imp["line"]

            # Case 1: Relative Import (Level > 0)
            if is_relative and level > 0:
                # Calculate target base directory
                up_levels = level - 1
                if up_levels > len(file_dir_parts):
                    # Relative import escapes project root
                    unresolved_findings.append(
                        {
                            "type": "possible_unresolved_local_import",
                            "path": file_path,
                            "import": f"from {'.' * level}{module} import {name}",
                            "message": (
                                f"Possible unresolved relative import: 'from {'.' * level}{module} "
                                f"import {name}' escapes project root."
                            ),
                            "line": line,
                            "severity": "warning",
                        }
                    )
                    continue

                target_dir_parts = file_dir_parts[: len(file_dir_parts) - up_levels]
                base_dir = "/".join(target_dir_parts)

                # Module candidate paths
                candidates = []
                target_sub = module.replace(".", "/") if module else ""

                if target_sub:
                    full_mod_path = f"{base_dir}/{target_sub}".strip("/")
                    candidates.extend(
                        [
                            f"{full_mod_path}.py",
                            f"{full_mod_path}/__init__.py",
                            f"{full_mod_path}/{name}.py",
                            f"{full_mod_path}/{name}/__init__.py",
                        ]
                    )
                else:
                    # e.g. from . import name
                    full_name_path = f"{base_dir}/{name}".strip("/")
                    candidates.extend(
                        [
                            f"{full_name_path}.py",
                            f"{full_name_path}/__init__.py",
                            f"{base_dir}/__init__.py" if base_dir else "__init__.py",
                        ]
                    )

                if not any(c in all_project_files for c in candidates):
                    unresolved_findings.append(
                        {
                            "type": "possible_unresolved_local_import",
                            "path": file_path,
                            "import": f"from {'.' * level}{module} import {name}",
                            "message": (
                                f"Possible unresolved relative import: target module for 'from "
                                f"{'.' * level}{module} import {name}' not found locally."
                            ),
                            "line": line,
                            "severity": "warning",
                        }
                    )

            # Case 2: Absolute Import (Level == 0)
            elif not is_relative:
                full_mod = module or name
                if not full_mod:
                    continue

                top_pkg = full_mod.split(".")[0].lower()

                # Skip standard library modules completely
                if top_pkg in STDLIB_MODULES:
                    continue

                # Only evaluate if top_pkg clearly matches a local project package
                if top_pkg in local_roots:
                    # Check if the target module path exists
                    mod_path = full_mod.replace(".", "/")
                    parent_path = "/".join(full_mod.split(".")[:-1]).replace(".", "/")

                    possible_paths = [
                        f"{mod_path}.py",
                        f"{mod_path}/__init__.py",
                    ]
                    if parent_path:
                        possible_paths.extend(
                            [
                                f"{parent_path}.py",
                                f"{parent_path}/__init__.py",
                            ]
                        )

                    if not any(cand in all_project_files for cand in possible_paths):
                        unresolved_findings.append(
                            {
                                "type": "possible_unresolved_local_import",
                                "path": file_path,
                                "import": f"import {full_mod}" if not imp["is_from"] else f"from {module} import {name}",
                                "message": (
                                    f"Possible unresolved local import: '{full_mod}' matches a local "
                                    f"project package root but target file was not found."
                                ),
                                "line": line,
                                "severity": "warning",
                            }
                        )

    return unresolved_findings


def analyze_python_code(data: bytes) -> Dict[str, Any]:
    """Parse and extract structural evidence from Python source files in a ZIP archive.

    Reuses validate_archive. Never extracts files to disk or executes code.

    Args:
        data: Raw archive bytes.

    Returns:
        Dict containing:
            - status (str): "success" or "error"
            - validation (dict): Report from validate_archive
            - summary (dict): Aggregate metrics for Python files, functions, classes, imports, etc.
            - files (list[dict]): Detailed AST analysis per Python file
            - findings (list[dict]): Syntax errors, entry points, and unresolved local imports
            - issues (list[str]): General validation or processing issues
    """
    # 1. Validate the archive first
    validation = validate_archive(data)

    empty_summary = {
        "total_python_files": 0,
        "parsed_files": 0,
        "syntax_error_files": 0,
        "function_count": 0,
        "class_count": 0,
        "import_count": 0,
        "entry_point_candidates": [],
    }

    if not validation["valid"]:
        return {
            "status": "error",
            "validation": validation,
            "summary": empty_summary,
            "files": [],
            "findings": [],
            "issues": validation.get("issues", ["Archive validation failed."]),
        }

    files: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    entry_point_candidates: List[str] = []

    total_functions = 0
    total_classes = 0
    total_imports = 0
    syntax_error_files = 0
    parsed_files = 0

    all_project_files: Set[str] = set()

    try:
        archive_buffer = io.BytesIO(data)
        with zipfile.ZipFile(archive_buffer, "r") as zf:
            infolist = zf.infolist()

            # First pass: collect all valid non-ignored project file paths
            for info in infolist:
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
                dir_components = parts if is_dir else parts[:-1]
                if any(comp.lower() in IGNORED_DIRECTORIES for comp in dir_components):
                    continue

                if not is_dir:
                    all_project_files.add(norm_path)

            # Second pass: analyze Python files
            for info in infolist:
                raw_filename = info.filename
                norm_path = raw_filename.replace("\\", "/").strip("/")
                if not norm_path or norm_path not in all_project_files:
                    continue

                if not (norm_path.endswith(".py") or norm_path.endswith(".pyw")):
                    continue

                # Read source safely in memory
                try:
                    raw_bytes = zf.read(info)
                    # Attempt decode (utf-8 with fallback)
                    try:
                        source_code = raw_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        source_code = raw_bytes.decode("latin-1")
                except Exception as read_exc:
                    syntax_error_files += 1
                    err_msg = f"Failed to read file content: {type(read_exc).__name__}"
                    files.append(
                        {
                            "path": norm_path,
                            "line_count": 0,
                            "parsed": False,
                            "syntax_error": err_msg,
                            "functions": [],
                            "classes": [],
                            "imports": [],
                            "entry_point_indicators": [],
                            "has_main_guard": False,
                        }
                    )
                    findings.append(
                        {
                            "type": "read_error",
                            "path": norm_path,
                            "message": err_msg,
                            "line": None,
                            "severity": "error",
                        }
                    )
                    continue

                line_count = len(source_code.splitlines())

                # Parse AST safely
                try:
                    tree = ast.parse(source_code, filename=norm_path)
                    parsed_files += 1
                except SyntaxError as syn_exc:
                    syntax_error_files += 1
                    err_msg = f"SyntaxError at line {syn_exc.lineno}: {syn_exc.msg}"
                    files.append(
                        {
                            "path": norm_path,
                            "line_count": line_count,
                            "parsed": False,
                            "syntax_error": err_msg,
                            "functions": [],
                            "classes": [],
                            "imports": [],
                            "entry_point_indicators": [],
                            "has_main_guard": False,
                        }
                    )
                    findings.append(
                        {
                            "type": "syntax_error",
                            "path": norm_path,
                            "message": err_msg,
                            "line": syn_exc.lineno,
                            "severity": "error",
                        }
                    )
                    continue

                # Extract functions, classes, and methods
                file_functions: List[Dict[str, Any]] = []
                file_classes: List[Dict[str, Any]] = []

                for node in tree.body:
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        file_functions.append(
                            {
                                "name": node.name,
                                "line": node.lineno,
                                "scope": "module",
                                "is_async": isinstance(node, ast.AsyncFunctionDef),
                            }
                        )
                    elif isinstance(node, ast.ClassDef):
                        class_methods: List[Dict[str, Any]] = []
                        bases: List[str] = []
                        for b in node.bases:
                            try:
                                bases.append(ast.unparse(b))
                            except Exception:
                                bases.append(getattr(b, "id", str(b)))

                        for item in node.body:
                            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                class_methods.append(
                                    {
                                        "name": item.name,
                                        "line": item.lineno,
                                        "is_async": isinstance(item, ast.AsyncFunctionDef),
                                    }
                                )
                                file_functions.append(
                                    {
                                        "name": item.name,
                                        "line": item.lineno,
                                        "scope": node.name,
                                        "is_async": isinstance(item, ast.AsyncFunctionDef),
                                    }
                                )

                        file_classes.append(
                            {
                                "name": node.name,
                                "line": node.lineno,
                                "bases": bases,
                                "methods": class_methods,
                            }
                        )

                # Extract imports
                file_imports: List[Dict[str, Any]] = []
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            file_imports.append(
                                {
                                    "module": alias.name,
                                    "name": alias.name,
                                    "alias": alias.asname,
                                    "is_from": False,
                                    "is_relative": False,
                                    "level": 0,
                                    "line": node.lineno,
                                }
                            )
                    elif isinstance(node, ast.ImportFrom):
                        mod_name = node.module or ""
                        is_rel = (node.level or 0) > 0
                        for alias in node.names:
                            file_imports.append(
                                {
                                    "module": mod_name,
                                    "name": alias.name,
                                    "alias": alias.asname,
                                    "is_from": True,
                                    "is_relative": is_rel,
                                    "level": node.level or 0,
                                    "line": node.lineno,
                                }
                            )

                # Sort imports by line number for clean presentation
                file_imports.sort(key=lambda x: x["line"])

                # Check entry-point indicators
                has_guard = _check_main_guard(tree)
                entry_indicators: List[str] = []
                if has_guard:
                    entry_indicators.append("if __name__ == '__main__'")

                file_base = os.path.basename(norm_path).lower()
                if file_base in {"main.py", "__main__.py", "app.py", "run.py", "manage.py", "cli.py"}:
                    entry_indicators.append(f"filename: {file_base}")

                if entry_indicators:
                    entry_point_candidates.append(norm_path)
                    findings.append(
                        {
                            "type": "entry_point_candidate",
                            "path": norm_path,
                            "message": f"Likely entry point identified: {', '.join(entry_indicators)}.",
                            "line": 1,
                            "severity": "info",
                        }
                    )

                total_functions += len(file_functions)
                total_classes += len(file_classes)
                total_imports += len(file_imports)

                files.append(
                    {
                        "path": norm_path,
                        "line_count": line_count,
                        "parsed": True,
                        "syntax_error": None,
                        "functions": file_functions,
                        "classes": file_classes,
                        "imports": file_imports,
                        "entry_point_indicators": entry_indicators,
                        "has_main_guard": has_guard,
                    }
                )

        # 3. Third pass: check unresolved local imports
        unresolved_imports = _check_unresolved_local_imports(files, all_project_files)
        findings.extend(unresolved_imports)

    except Exception as exc:
        return {
            "status": "error",
            "validation": {
                "valid": False,
                "file_count": 0,
                "total_uncompressed_size": 0,
                "issues": [f"Failed to analyze Python code: {type(exc).__name__}"],
            },
            "summary": empty_summary,
            "files": [],
            "findings": [],
            "issues": [f"Analysis exception: {type(exc).__name__}"],
        }

    summary = {
        "total_python_files": len(files),
        "parsed_files": parsed_files,
        "syntax_error_files": syntax_error_files,
        "function_count": total_functions,
        "class_count": total_classes,
        "import_count": total_imports,
        "entry_point_candidates": entry_point_candidates,
    }

    return {
        "status": "success",
        "validation": validation,
        "summary": summary,
        "files": files,
        "findings": findings,
        "issues": [],
    }
