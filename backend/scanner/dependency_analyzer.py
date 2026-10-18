"""TRASHAK AI - Dependency and Project Health Analyzer.

Analyzes uploaded software project ZIP archives to identify declared dependencies,
configuration gaps, manifest integrity, and project health indicators.
Reuses the secure validator, file inventory scanner, and Python code structure analyzer.
Never extracts files to disk or executes uploaded code.
"""

import io
import json
import os
import re
import xml.etree.ElementTree as ET
import zipfile
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # Python 3.10
    except ImportError:
        tomllib = None

from backend.core.archive_validator import validate_archive
from backend.core.file_inventory import build_inventory
from backend.scanner.code_analyzer import STDLIB_MODULES, analyze_python_code

# Canonical mapping of common Python import names to package names on PyPI
# where import name differs significantly from the package distribution name
IMPORT_TO_PACKAGE_MAP: Dict[str, Set[str]] = {
    "yaml": {"pyyaml"},
    "pil": {"pillow"},
    "cv2": {"opencv-python", "opencv-python-headless"},
    "bs4": {"beautifulsoup4"},
    "sklearn": {"scikit-learn"},
    "openssl": {"pyopenssl"},
    "git": {"gitpython"},
    "dotenv": {"python-dotenv"},
    "jose": {"python-jose"},
    "multipart": {"python-multipart"},
    "dateutil": {"python-dateutil"},
    "magic": {"python-magic"},
    "pptx": {"python-pptx"},
    "docx": {"python-docx"},
    "serial": {"pyserial"},
    "jwt": {"pyjwt"},
    "fitz": {"pymupdf"},
    "websocket": {"websocket-client"},
    "dns": {"dnspython"},
    "pkg_resources": {"setuptools"},
    "setuptools": {"setuptools"},
}


def _normalize_name(name: str) -> str:
    """Normalize a package or module name for comparison (PEP 503 convention)."""
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def _parse_requirements_txt(content: str, path: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Parse a requirements.txt file conservatively."""
    deps: List[Dict[str, Any]] = []
    is_dev = "dev" in path.lower() or "test" in path.lower()

    for raw_line in content.splitlines():
        line = raw_line.strip()
        # Remove comments and trailing comments
        line = re.sub(r"\s+[#;].*$", "", line).strip()
        if not line or line.startswith(("#", ";")):
            continue

        # Skip pip options like -r, -i, --extra-index-url
        if line.startswith("-") or line.startswith("--"):
            continue

        # Parse package name and version specifier
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:\[[^\]]*\])?(.*)$", line)
        if match:
            pkg_name = match.group(1).strip()
            raw_spec = line
            deps.append(
                {
                    "name": _normalize_name(pkg_name),
                    "raw_spec": raw_spec,
                    "manifest_path": path,
                    "ecosystem": "python",
                    "is_dev": is_dev,
                }
            )

    return deps, None


def _parse_pyproject_toml(content: str, path: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Parse a pyproject.toml file for standard dependencies and tool configurations."""
    if tomllib is None:
        return [], "TOML parser (tomllib/tomli) is not available."

    try:
        data = tomllib.loads(content)
    except Exception as exc:
        return [], f"TOML syntax error: {str(exc)}"

    deps: List[Dict[str, Any]] = []

    # Standard PEP 621 [project.dependencies]
    project = data.get("project", {})
    if isinstance(project, dict):
        for dep in project.get("dependencies", []):
            if isinstance(dep, str):
                match = re.match(r"^([a-zA-Z0-9_\-\.]+)", dep.strip())
                if match:
                    deps.append(
                        {
                            "name": _normalize_name(match.group(1)),
                            "raw_spec": dep.strip(),
                            "manifest_path": path,
                            "ecosystem": "python",
                            "is_dev": False,
                        }
                    )

        # Optional dependencies (dev, test, docs)
        for group, group_deps in project.get("optional-dependencies", {}).items():
            if isinstance(group_deps, list):
                is_dev = any(k in group.lower() for k in ["dev", "test", "lint", "doc"])
                for dep in group_deps:
                    if isinstance(dep, str):
                        match = re.match(r"^([a-zA-Z0-9_\-\.]+)", dep.strip())
                        if match:
                            deps.append(
                                {
                                    "name": _normalize_name(match.group(1)),
                                    "raw_spec": dep.strip(),
                                    "manifest_path": path,
                                    "ecosystem": "python",
                                    "is_dev": is_dev,
                                }
                            )

    # Poetry [tool.poetry.dependencies]
    tool = data.get("tool", {})
    if isinstance(tool, dict):
        poetry = tool.get("poetry", {})
        if isinstance(poetry, dict):
            for pkg, spec in poetry.get("dependencies", {}).items():
                if pkg.lower() != "python":
                    deps.append(
                        {
                            "name": _normalize_name(pkg),
                            "raw_spec": f"{pkg} {spec}" if isinstance(spec, str) else pkg,
                            "manifest_path": path,
                            "ecosystem": "python",
                            "is_dev": False,
                        }
                    )

            # Poetry dev dependencies
            for pkg, spec in poetry.get("dev-dependencies", {}).items():
                deps.append(
                    {
                        "name": _normalize_name(pkg),
                        "raw_spec": f"{pkg} {spec}" if isinstance(spec, str) else pkg,
                        "manifest_path": path,
                        "ecosystem": "python",
                        "is_dev": True,
                    }
                )

            # Poetry group dependencies
            for group_name, group_data in poetry.get("group", {}).items():
                if isinstance(group_data, dict):
                    is_dev = any(k in group_name.lower() for k in ["dev", "test", "lint"])
                    for pkg, spec in group_data.get("dependencies", {}).items():
                        deps.append(
                            {
                                "name": _normalize_name(pkg),
                                "raw_spec": f"{pkg} {spec}" if isinstance(spec, str) else pkg,
                                "manifest_path": path,
                                "ecosystem": "python",
                                "is_dev": is_dev,
                            }
                        )

    return deps, None


def _parse_pipfile(content: str, path: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Parse Pipfile for packages and dev-packages."""
    if tomllib is not None:
        try:
            data = tomllib.loads(content)
            deps = []
            for pkg, spec in data.get("packages", {}).items():
                deps.append(
                    {
                        "name": _normalize_name(pkg),
                        "raw_spec": f"{pkg} = {spec}" if isinstance(spec, str) else pkg,
                        "manifest_path": path,
                        "ecosystem": "python",
                        "is_dev": False,
                    }
                )
            for pkg, spec in data.get("dev-packages", {}).items():
                deps.append(
                    {
                        "name": _normalize_name(pkg),
                        "raw_spec": f"{pkg} = {spec}" if isinstance(spec, str) else pkg,
                        "manifest_path": path,
                        "ecosystem": "python",
                        "is_dev": True,
                    }
                )
            return deps, None
        except Exception as exc:
            return [], f"Pipfile parse error: {str(exc)}"

    # Line-based fallback
    deps = []
    current_section = None
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("[packages]"):
            current_section = "packages"
        elif line.startswith("[dev-packages]"):
            current_section = "dev-packages"
        elif line.startswith("["):
            current_section = None
        elif current_section and "=" in line:
            pkg = line.split("=")[0].strip()
            deps.append(
                {
                    "name": _normalize_name(pkg),
                    "raw_spec": line,
                    "manifest_path": path,
                    "ecosystem": "python",
                    "is_dev": current_section == "dev-packages",
                }
            )
    return deps, None


def _parse_package_json(content: str, path: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Parse JavaScript / Node.js package.json manifest."""
    try:
        data = json.loads(content)
    except Exception as exc:
        return [], f"JSON syntax error: {str(exc)}"

    if not isinstance(data, dict):
        return [], "Root JSON element is not an object."

    deps: List[Dict[str, Any]] = []

    for pkg, version in data.get("dependencies", {}).items():
        deps.append(
            {
                "name": pkg.lower().strip(),
                "raw_spec": f"{pkg}@{version}",
                "manifest_path": path,
                "ecosystem": "javascript",
                "is_dev": False,
            }
        )

    for pkg, version in data.get("devDependencies", {}).items():
        deps.append(
            {
                "name": pkg.lower().strip(),
                "raw_spec": f"{pkg}@{version}",
                "manifest_path": path,
                "ecosystem": "javascript",
                "is_dev": True,
            }
        )

    return deps, None


def _parse_composer_json(content: str, path: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Parse PHP composer.json manifest."""
    try:
        data = json.loads(content)
    except Exception as exc:
        return [], f"JSON syntax error: {str(exc)}"

    deps: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        for pkg, ver in data.get("require", {}).items():
            deps.append(
                {
                    "name": pkg.lower().strip(),
                    "raw_spec": f"{pkg}:{ver}",
                    "manifest_path": path,
                    "ecosystem": "php",
                    "is_dev": False,
                }
            )
        for pkg, ver in data.get("require-dev", {}).items():
            deps.append(
                {
                    "name": pkg.lower().strip(),
                    "raw_spec": f"{pkg}:{ver}",
                    "manifest_path": path,
                    "ecosystem": "php",
                    "is_dev": True,
                }
            )
    return deps, None


def _parse_cargo_toml(content: str, path: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Parse Rust Cargo.toml manifest."""
    if tomllib is None:
        return [], None
    try:
        data = tomllib.loads(content)
    except Exception as exc:
        return [], f"TOML syntax error: {str(exc)}"

    deps: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        for pkg, spec in data.get("dependencies", {}).items():
            deps.append(
                {
                    "name": pkg.lower().strip(),
                    "raw_spec": f"{pkg} = {spec}" if isinstance(spec, str) else pkg,
                    "manifest_path": path,
                    "ecosystem": "rust",
                    "is_dev": False,
                }
            )
        for pkg, spec in data.get("dev-dependencies", {}).items():
            deps.append(
                {
                    "name": pkg.lower().strip(),
                    "raw_spec": f"{pkg} = {spec}" if isinstance(spec, str) else pkg,
                    "manifest_path": path,
                    "ecosystem": "rust",
                    "is_dev": True,
                }
            )
    return deps, None


def _parse_pom_xml(content: str, path: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Parse Java Maven pom.xml manifest."""
    try:
        root = ET.fromstring(content)
    except Exception as exc:
        return [], f"XML syntax error: {str(exc)}"

    deps: List[Dict[str, Any]] = []
    # Strip XML namespaces for straightforward element lookup
    for elem in root.iter():
        if elem.tag.endswith("dependency"):
            group_id = ""
            artifact_id = ""
            for child in elem:
                if child.tag.endswith("groupId"):
                    group_id = (child.text or "").strip()
                elif child.tag.endswith("artifactId"):
                    artifact_id = (child.text or "").strip()
            if artifact_id:
                name = f"{group_id}:{artifact_id}" if group_id else artifact_id
                deps.append(
                    {
                        "name": name.lower(),
                        "raw_spec": name,
                        "manifest_path": path,
                        "ecosystem": "java",
                        "is_dev": False,
                    }
                )
    return deps, None


def _parse_go_mod(content: str, path: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Parse Go go.mod manifest."""
    deps: List[Dict[str, Any]] = []
    in_require_block = False

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue

        if line.startswith("require ("):
            in_require_block = True
            continue
        elif in_require_block and line == ")":
            in_require_block = False
            continue

        if in_require_block:
            parts = line.split()
            if parts:
                deps.append(
                    {
                        "name": parts[0].lower(),
                        "raw_spec": line,
                        "manifest_path": path,
                        "ecosystem": "go",
                        "is_dev": False,
                    }
                )
        elif line.startswith("require "):
            parts = line[len("require ") :].strip().split()
            if parts:
                deps.append(
                    {
                        "name": parts[0].lower(),
                        "raw_spec": line,
                        "manifest_path": path,
                        "ecosystem": "go",
                        "is_dev": False,
                    }
                )

    return deps, None


def analyze_dependencies(data: bytes) -> Dict[str, Any]:
    """Analyze declared dependencies and project health indicators in an uploaded archive.

    Reuses validate_archive, build_inventory, and analyze_python_code.
    Operates strictly in-memory without extracting files or executing code.

    Args:
        data: Raw archive bytes.

    Returns:
        Dict containing:
            - status (str): "success" or "error"
            - validation (dict): Report from validate_archive
            - summary (dict): Counts for manifests, dependencies, comparisons, and health findings
            - manifests (list[dict]): Discovered manifests and their declared packages
            - dependencies (list[dict]): Normalized declared dependencies list
            - findings (list[dict]): Structured health findings with severity, evidence, and confidence
            - issues (list[str]): General validation or processing issues
    """
    # 1. Validate the archive first
    validation = validate_archive(data)

    empty_summary = {
        "manifests_discovered": 0,
        "dependencies_declared": 0,
        "import_comparisons_performed": 0,
        "health_findings_count": 0,
        "ecosystems_detected": [],
    }

    if not validation["valid"]:
        return {
            "status": "error",
            "validation": validation,
            "summary": empty_summary,
            "manifests": [],
            "dependencies": [],
            "findings": [],
            "issues": validation.get("issues", ["Archive validation failed."]),
        }

    # 2. Obtain file inventory and Python code structure
    inventory_res = build_inventory(data)
    code_res = analyze_python_code(data)

    inventory_files = inventory_res.get("files", [])
    all_paths = {f["path"] for f in inventory_files}
    path_by_name = {f["name"].lower(): f["path"] for f in inventory_files}

    manifests: List[Dict[str, Any]] = []
    dependencies: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    ecosystems_detected: Set[str] = set()

    import_comparisons_performed = 0

    # 3. Read and parse manifests from in-memory ZIP
    try:
        archive_buffer = io.BytesIO(data)
        with zipfile.ZipFile(archive_buffer, "r") as zf:
            for f in inventory_files:
                path = f["path"]
                fname_lower = f["name"].lower()

                # Determine manifest parser
                parser_fn = None
                ecosystem = None
                manifest_type = f["name"]

                if (
                    fname_lower == "requirements.txt"
                    or (fname_lower.startswith("requirements") and fname_lower.endswith(".txt"))
                ):
                    parser_fn = _parse_requirements_txt
                    ecosystem = "python"
                elif fname_lower == "pyproject.toml":
                    parser_fn = _parse_pyproject_toml
                    ecosystem = "python"
                elif fname_lower == "pipfile":
                    parser_fn = _parse_pipfile
                    ecosystem = "python"
                elif fname_lower == "package.json":
                    parser_fn = _parse_package_json
                    ecosystem = "javascript"
                elif fname_lower == "composer.json":
                    parser_fn = _parse_composer_json
                    ecosystem = "php"
                elif fname_lower == "cargo.toml":
                    parser_fn = _parse_cargo_toml
                    ecosystem = "rust"
                elif fname_lower == "pom.xml":
                    parser_fn = _parse_pom_xml
                    ecosystem = "java"
                elif fname_lower == "go.mod":
                    parser_fn = _parse_go_mod
                    ecosystem = "go"
                elif fname_lower in {
                    "package-lock.json",
                    "yarn.lock",
                    "pnpm-lock.yaml",
                    "poetry.lock",
                    "pipfile.lock",
                    "cargo.lock",
                    "composer.lock",
                }:
                    # Recognize lockfiles as manifests
                    manifests.append(
                        {
                            "path": path,
                            "ecosystem": "javascript" if "package" in fname_lower or "yarn" in fname_lower or "pnpm" in fname_lower else "python",
                            "manifest_type": f["name"],
                            "parsed": True,
                            "declared_dependencies": [],
                            "error": None,
                        }
                    )
                    continue

                if parser_fn and ecosystem:
                    ecosystems_detected.add(ecosystem)
                    try:
                        raw_bytes = zf.read(path)
                        try:
                            content = raw_bytes.decode("utf-8")
                        except UnicodeDecodeError:
                            content = raw_bytes.decode("latin-1")

                        parsed_deps, parse_err = parser_fn(content, path)
                        if parse_err:
                            manifests.append(
                                {
                                    "path": path,
                                    "ecosystem": ecosystem,
                                    "manifest_type": manifest_type,
                                    "parsed": False,
                                    "declared_dependencies": [],
                                    "error": parse_err,
                                }
                            )
                            findings.append(
                                {
                                    "severity": "error",
                                    "category": "malformed_manifest",
                                    "description": f"Malformed dependency manifest '{path}': {parse_err}",
                                    "evidence": f"File '{path}' could not be parsed: {parse_err}",
                                    "confidence": "confirmed",
                                }
                            )
                        else:
                            dep_names = [d["name"] for d in parsed_deps]
                            manifests.append(
                                {
                                    "path": path,
                                    "ecosystem": ecosystem,
                                    "manifest_type": manifest_type,
                                    "parsed": True,
                                    "declared_dependencies": dep_names,
                                    "error": None,
                                }
                            )
                            dependencies.extend(parsed_deps)

                    except Exception as read_exc:
                        manifests.append(
                            {
                                "path": path,
                                "ecosystem": ecosystem,
                                "manifest_type": manifest_type,
                                "parsed": False,
                                "declared_dependencies": [],
                                "error": f"Read error: {type(read_exc).__name__}",
                            }
                        )
                        findings.append(
                            {
                                "severity": "error",
                                "category": "malformed_manifest",
                                "description": f"Could not read manifest '{path}': {type(read_exc).__name__}",
                                "evidence": f"Read exception: {type(read_exc).__name__}",
                                "confidence": "confirmed",
                            }
                        )

    except Exception as exc:
        return {
            "status": "error",
            "validation": {
                "valid": False,
                "file_count": 0,
                "total_uncompressed_size": 0,
                "issues": [f"Failed to analyze dependencies: {type(exc).__name__}"],
            },
            "summary": empty_summary,
            "manifests": [],
            "dependencies": [],
            "findings": [],
            "issues": [f"Dependency analysis exception: {type(exc).__name__}"],
        }

    # 4. Compare Python imports against declared dependencies
    python_files = code_res.get("files", [])
    if python_files:
        ecosystems_detected.add("python")

    # Set of declared Python package names (normalized)
    declared_py_packages: Set[str] = {
        d["name"] for d in dependencies if d["ecosystem"] == "python"
    }

    # Discover local project package roots to exclude local modules
    local_roots: Set[str] = set()
    for p in all_paths:
        if p.endswith((".py", ".pyw")):
            parts = p.split("/")
            if len(parts) > 1:
                local_roots.add(parts[0].lower())
            else:
                base_name = os.path.splitext(parts[0])[0].lower()
                local_roots.add(base_name)

    # Track seen imported modules to avoid duplicate findings
    seen_undeclared: Set[str] = set()

    for py_file in python_files:
        f_path = py_file["path"]
        for imp in py_file.get("imports", []):
            is_relative = imp["is_relative"]
            if is_relative:
                # Relative imports are always local
                continue

            full_mod = imp["module"] or imp["name"]
            if not full_mod:
                continue

            top_pkg = full_mod.split(".")[0].lower()

            # Skip standard library modules
            if top_pkg in STDLIB_MODULES:
                continue

            # Skip local project package imports
            if top_pkg in local_roots:
                continue

            import_comparisons_performed += 1

            # Check if declared directly or through mapping
            normalized_import = _normalize_name(top_pkg)
            candidate_packages = {normalized_import}
            if top_pkg in IMPORT_TO_PACKAGE_MAP:
                candidate_packages.update(
                    _normalize_name(pkg) for pkg in IMPORT_TO_PACKAGE_MAP[top_pkg]
                )

            is_declared = bool(candidate_packages & declared_py_packages)

            if not is_declared and normalized_import not in seen_undeclared:
                seen_undeclared.add(normalized_import)
                # Has Python manifest been discovered at all?
                has_py_manifest = any(
                    m["ecosystem"] == "python" and m["parsed"] for m in manifests
                )
                evidence_note = (
                    f"Imported in '{f_path}' (line {imp['line']}). "
                    f"Declared Python packages: {', '.join(sorted(declared_py_packages)) if declared_py_packages else 'None'}."
                )

                findings.append(
                    {
                        "severity": "warning",
                        "category": "dependency_gap",
                        "description": (
                            f"Possible undeclared dependency: '{top_pkg}' is imported but was not "
                            f"found in declared manifests."
                        ),
                        "evidence": evidence_note,
                        "confidence": "uncertain",
                    }
                )

    # 5. Project Health Inspections
    categories_summary = inventory_res.get("summary", {}).get("counts_by_category", {})
    doc_count = categories_summary.get("documentation", 0)
    test_count = categories_summary.get("test", 0)
    source_count = categories_summary.get("source_code", 0)

    # Health Check A: Missing README or Documentation
    has_readme = any(
        name.startswith("readme") for name in path_by_name.keys()
    )
    if not has_readme and doc_count == 0:
        findings.append(
            {
                "severity": "warning",
                "category": "documentation_gap",
                "description": "Project lacks a README or primary documentation file.",
                "evidence": "No README.md, README.rst, or documentation files found in the archive.",
                "confidence": "confirmed",
            }
        )

    # Health Check B: Missing Manifests when source code is present
    if source_count > 0 and not manifests:
        findings.append(
            {
                "severity": "warning",
                "category": "manifest_gap",
                "description": (
                    f"Project contains {source_count} source file(s) but lacks a standard "
                    "dependency manifest (e.g., requirements.txt, pyproject.toml, package.json)."
                ),
                "evidence": f"Found {source_count} source file(s) and 0 recognized manifest files.",
                "confidence": "confirmed",
            }
        )

    # Health Check C: Missing Automated Tests
    if source_count > 0 and test_count == 0:
        findings.append(
            {
                "severity": "info",
                "category": "test_gap",
                "description": "No automated test files or test directories (e.g., tests/, test/) were identified.",
                "evidence": f"Found {source_count} source file(s) but 0 test files in the archive.",
                "confidence": "confirmed",
            }
        )

    # Health Check D: Missing .gitignore file
    if ".gitignore" not in path_by_name:
        findings.append(
            {
                "severity": "info",
                "category": "configuration_gap",
                "description": "Project lacks a .gitignore file.",
                "evidence": "No .gitignore found in repository root.",
                "confidence": "confirmed",
            }
        )

    # Health Check E: Entry Point Detection Report
    entry_candidates = code_res.get("summary", {}).get("entry_point_candidates", [])
    if python_files:
        if not entry_candidates:
            findings.append(
                {
                    "severity": "info",
                    "category": "entry_point_gap",
                    "description": (
                        "No standard application entry point (e.g., main.py, app.py, or "
                        "'if __name__ == \"__main__\"') was detected."
                    ),
                    "evidence": f"Analyzed {len(python_files)} Python file(s) with no detected entry guards.",
                    "confidence": "uncertain",
                }
            )
        else:
            findings.append(
                {
                    "severity": "info",
                    "category": "entry_point_detected",
                    "description": f"Identified {len(entry_candidates)} entry-point candidate(s): {', '.join(entry_candidates)}.",
                    "evidence": f"Entry-point candidate paths: {', '.join(entry_candidates)}.",
                    "confidence": "confirmed",
                }
            )

    summary = {
        "manifests_discovered": len(manifests),
        "dependencies_declared": len(dependencies),
        "import_comparisons_performed": import_comparisons_performed,
        "health_findings_count": len(findings),
        "ecosystems_detected": sorted(list(ecosystems_detected)),
    }

    return {
        "status": "success",
        "validation": validation,
        "summary": summary,
        "manifests": manifests,
        "dependencies": dependencies,
        "findings": findings,
        "issues": [],
    }
