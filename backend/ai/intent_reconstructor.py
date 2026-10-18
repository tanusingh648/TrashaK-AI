"""TRASHAK AI - Evidence-Based Project Intent Reconstructor.

Infers the intended purpose, architectural patterns, likely features, and health
indicators of an abandoned software project by synthesizing evidence across
documentation, file topology, AST structural code analysis, and dependency manifests.
Distinguishes verified observations from inferences, highlights conflicting evidence,
and never executes uploaded code or relies on external models.
"""

import io
import os
import re
import zipfile
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.core.archive_validator import validate_archive
from backend.core.file_inventory import build_inventory
from backend.scanner.code_analyzer import analyze_python_code
from backend.scanner.dependency_analyzer import analyze_dependencies

# Standard architectural patterns mapped to framework dependencies
FRAMEWORK_PATTERNS: Dict[str, Dict[str, str]] = {
    "fastapi": {
        "framework": "FastAPI",
        "architecture": "Asynchronous REST API / Web Microservice",
        "ecosystem": "Python",
    },
    "flask": {
        "framework": "Flask",
        "architecture": "Lightweight Web Application / REST Service",
        "ecosystem": "Python",
    },
    "django": {
        "framework": "Django",
        "architecture": "Full-Stack Web Application (Model-View-Template)",
        "ecosystem": "Python",
    },
    "streamlit": {
        "framework": "Streamlit",
        "architecture": "Interactive Data Application / Machine Learning Dashboard",
        "ecosystem": "Python",
    },
    "tornado": {
        "framework": "Tornado",
        "architecture": "Asynchronous Web Server / Real-time Service",
        "ecosystem": "Python",
    },
    "express": {
        "framework": "Express.js",
        "architecture": "Node.js REST API / Server-Side Application",
        "ecosystem": "JavaScript",
    },
    "react": {
        "framework": "React",
        "architecture": "Single Page Application (SPA) Client Interface",
        "ecosystem": "JavaScript",
    },
    "vue": {
        "framework": "Vue.js",
        "architecture": "Progressive Client-Side Web Application",
        "ecosystem": "JavaScript",
    },
    "click": {
        "framework": "Click",
        "architecture": "Command-Line Interface (CLI) Tool",
        "ecosystem": "Python",
    },
    "typer": {
        "framework": "Typer",
        "architecture": "Type-Driven Command-Line Interface (CLI) Tool",
        "ecosystem": "Python",
    },
    "pytest": {
        "framework": "Pytest",
        "architecture": "Automated Software Test Suite",
        "ecosystem": "Python",
    },
    "pandas": {
        "framework": "Pandas",
        "architecture": "Data Processing & Tabular Analytics Pipeline",
        "ecosystem": "Python",
    },
    "torch": {
        "framework": "PyTorch",
        "architecture": "Deep Learning / Neural Network Application",
        "ecosystem": "Python",
    },
    "tensorflow": {
        "framework": "TensorFlow",
        "architecture": "Machine Learning Model Training / Inference Pipeline",
        "ecosystem": "Python",
    },
    "scikit-learn": {
        "framework": "Scikit-Learn",
        "architecture": "Statistical Machine Learning Model Pipeline",
        "ecosystem": "Python",
    },
}


def _read_bounded_text(zf: zipfile.ZipFile, path: str, max_chars: int = 10000) -> str:
    """Read bounded text content from a ZIP entry safely with multi-encoding fallback."""
    try:
        raw_bytes = zf.read(path)
        if len(raw_bytes) > max_chars * 2:
            raw_bytes = raw_bytes[: max_chars * 2]
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            text = raw_bytes.decode("latin-1", errors="replace")
        return text[:max_chars]
    except Exception:
        return ""


def _extract_readme_info(readme_text: str) -> Tuple[Optional[str], Optional[str], List[str]]:
    """Extract project title, high-level summary, and explicit features from README text."""
    project_name = None
    description = None
    features: List[str] = []

    lines = readme_text.splitlines()
    in_features = False

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # Extract H1 title
        if not project_name and stripped.startswith("#"):
            title = stripped.lstrip("#").strip()
            # Clean emojis, markdown badges, or punctuation
            title = re.sub(r"[^\w\s\-\.]", "", title).strip()
            if title and len(title) > 1:
                project_name = title
            continue

        # Extract features section
        if re.match(r"^#{1,3}\s*(features|capabilities|what it does|highlights|core functions)", stripped, re.IGNORECASE):
            in_features = True
            continue
        elif in_features and stripped.startswith("#"):
            in_features = False

        if in_features and (stripped.startswith(("- ", "* ", "+ ")) or re.match(r"^\d+\.\s+", stripped)):
            feat_text = re.sub(r"^[-*+\d\.]+\s+", "", stripped).strip()
            feat_text = re.sub(r"[*_`]", "", feat_text)
            if feat_text and len(feat_text) > 3 and len(features) < 8:
                features.append(feat_text)
            continue

        # Extract first non-header descriptive paragraph
        if not description and not stripped.startswith("#") and not stripped.startswith("[!") and not stripped.startswith("!["):
            if not (stripped.startswith("[") and stripped.endswith(")")) and len(stripped) > 15:
                description = stripped

    return project_name, description, features


def reconstruct_intent(data: bytes) -> Dict[str, Any]:
    """Reconstruct the probable purpose and architectural intent of an abandoned project.

    Combines verified facts from the archive validator, file inventory, Python code
    analyzer, and dependency health analyzer. Never executes uploaded code.

    Args:
        data: Raw archive bytes.

    Returns:
        Dict containing:
            - status (str): "success" or "error"
            - validation (dict): Report from validate_archive
            - project_name (str | None): Inferred or documented project title
            - probable_purpose (str): Inferred project purpose or statement of insufficiency
            - likely_features (list[dict]): Extracted or inferred feature capabilities
            - probable_architecture (dict): Detected architectural pattern and frameworks
            - likely_entry_points (list[dict]): Documented or structural execution entry points
            - incomplete_or_uncertain_areas (list[dict]): Gaps, conflicts, or missing components
            - evidence (list[dict]): Structured evidence items (fact, inference, conflict)
            - confidence (str): "high", "medium", or "low"
            - limitations (list[str]): Methodological boundaries and constraints
            - issues (list[str]): Validation or processing errors
    """
    # 1. Validate the archive first
    validation = validate_archive(data)

    if not validation["valid"]:
        return {
            "status": "error",
            "validation": validation,
            "project_name": None,
            "probable_purpose": "Project purpose could not be determined because archive validation failed.",
            "likely_features": [],
            "probable_architecture": {"pattern": "Unknown", "frameworks": [], "ecosystem": "Unknown"},
            "likely_entry_points": [],
            "incomplete_or_uncertain_areas": [],
            "evidence": [],
            "confidence": "low",
            "limitations": ["Archive is invalid or failed security validation."],
            "issues": validation.get("issues", ["Archive validation failed."]),
        }

    # 2. Run existing analyzers
    inventory_res = build_inventory(data)
    code_res = analyze_python_code(data)
    dependency_res = analyze_dependencies(data)

    evidence: List[Dict[str, Any]] = []
    likely_features: List[Dict[str, Any]] = []
    incomplete_areas: List[Dict[str, Any]] = []
    conflicts: List[Dict[str, Any]] = []

    inventory_files = inventory_res.get("files", [])
    path_by_name = {f["name"].lower(): f["path"] for f in inventory_files}
    all_paths = {f["path"] for f in inventory_files}

    project_name: Optional[str] = None
    readme_description: Optional[str] = None
    readme_features: List[str] = []

    # 3. Read README and documentation evidence safely
    readme_path = next((f["path"] for f in inventory_files if f["name"].lower().startswith("readme")), None)

    try:
        archive_buffer = io.BytesIO(data)
        with zipfile.ZipFile(archive_buffer, "r") as zf:
            if readme_path:
                readme_text = _read_bounded_text(zf, readme_path, max_chars=8000)
                if readme_text:
                    p_name, desc, feats = _extract_readme_info(readme_text)
                    if p_name:
                        project_name = p_name
                        evidence.append(
                            {
                                "type": "fact",
                                "source": readme_path,
                                "observation": f"Documented project title found in H1 header: '{p_name}'.",
                                "relevance": "Direct documentation evidence for project identity.",
                            }
                        )
                    if desc:
                        readme_description = desc
                        evidence.append(
                            {
                                "type": "fact",
                                "source": readme_path,
                                "observation": f"Documentation overview: '{desc[:150]}...'",
                                "relevance": "Primary author-stated purpose description.",
                            }
                        )
                    if feats:
                        readme_features = feats
                        for f_item in feats:
                            likely_features.append(
                                {
                                    "name": f_item,
                                    "source": readme_path,
                                    "evidence": f"Explicitly listed under documentation features in '{readme_path}'.",
                                    "confidence": "high",
                                }
                            )

    except Exception as exc:
        evidence.append(
            {
                "type": "fact",
                "source": readme_path or "archive",
                "observation": f"Could not read documentation: {type(exc).__name__}.",
                "relevance": "Documentation read error.",
            }
        )

    # 4. Check manifests for project name if not yet established
    for manifest in dependency_res.get("manifests", []):
        m_path = manifest["path"]
        evidence.append(
            {
                "type": "fact",
                "source": m_path,
                "observation": f"Declared manifest ({manifest['manifest_type']}) with packages: {manifest['declared_dependencies'][:6]}.",
                "relevance": "Confirms external software dependencies and tooling.",
            }
        )

    declared_deps = {d["name"] for d in dependency_res.get("dependencies", [])}

    # 5. Determine Frameworks & Architectural Pattern
    detected_frameworks: List[str] = []
    pattern_proposals: List[str] = []
    ecosystems = set(dependency_res.get("summary", {}).get("ecosystems_detected", []))

    for dep_name in declared_deps:
        norm = dep_name.lower().replace("_", "-")
        if norm in FRAMEWORK_PATTERNS:
            info = FRAMEWORK_PATTERNS[norm]
            detected_frameworks.append(info["framework"])
            pattern_proposals.append(info["architecture"])
            ecosystems.add(info["ecosystem"])
            evidence.append(
                {
                    "type": "inference",
                    "source": "dependencies",
                    "observation": f"Dependency '{norm}' indicates {info['architecture']} using {info['framework']}.",
                    "relevance": "Framework association.",
                }
            )

    # Check structural directory topology
    has_backend_dir = any(p.startswith("backend/") for p in all_paths)
    has_frontend_dir = any(p.startswith("frontend/") for p in all_paths)
    if has_backend_dir and has_frontend_dir:
        pattern_proposals.append("Decoupled Multi-Tier Full-Stack Application")
        evidence.append(
            {
                "type": "inference",
                "source": "file_topology",
                "observation": "Co-existence of distinct 'backend/' and 'frontend/' directories.",
                "relevance": "Architectural separation of API and user interface.",
            }
        )

    primary_pattern = pattern_proposals[0] if pattern_proposals else "Standalone Application / Script"
    if "Decoupled Multi-Tier Full-Stack Application" in pattern_proposals:
        primary_pattern = "Decoupled Multi-Tier Full-Stack Application"

    architecture = {
        "pattern": primary_pattern,
        "frameworks": sorted(list(set(detected_frameworks))),
        "ecosystem": ", ".join(sorted(ecosystems)) if ecosystems else "Generic",
    }

    # 6. Extract Code-Level Features from Functions & Classes
    code_files = code_res.get("files", [])
    for py_file in code_files:
        f_path = py_file["path"]
        for cls_item in py_file.get("classes", []):
            cls_name = cls_item["name"]
            # Exclude trivial base classes
            if cls_name.lower() not in {"test", "basetest", "config", "settings"}:
                likely_features.append(
                    {
                        "name": f"Module: {cls_name}",
                        "source": f_path,
                        "evidence": f"Class '{cls_name}' with methods: {[m['name'] for m in cls_item.get('methods', [])]}.",
                        "confidence": "medium",
                    }
                )

        # Look for API endpoints or functions
        for func_item in py_file.get("functions", []):
            if func_item["scope"] == "module":
                fn_name = func_item["name"]
                if any(k in fn_name.lower() for k in ["process", "convert", "scrape", "auth", "login", "export", "scan"]):
                    likely_features.append(
                        {
                            "name": f"Functionality: {fn_name}",
                            "source": f_path,
                            "evidence": f"Module-level function '{fn_name}' at line {func_item['line']}.",
                            "confidence": "medium",
                        }
                    )

    # 7. Collect Likely Entry Points
    entry_candidates = code_res.get("summary", {}).get("entry_point_candidates", [])
    likely_entry_points: List[Dict[str, Any]] = []

    for py_file in code_files:
        if py_file["path"] in entry_candidates:
            indicators = py_file.get("entry_point_indicators", [])
            likely_entry_points.append(
                {
                    "path": py_file["path"],
                    "indicators": indicators,
                    "evidence": f"Matched entry point indicators: {', '.join(indicators)}.",
                }
            )
            evidence.append(
                {
                    "type": "fact",
                    "source": py_file["path"],
                    "observation": f"Entry point confirmed: {', '.join(indicators)}.",
                    "relevance": "Direct application startup location.",
                }
            )

    # 8. Check for Conflicting Evidence
    if readme_description:
        desc_lower = readme_description.lower()
        # Conflict check: CLI vs heavy web backend
        if ("cli" in desc_lower or "command-line" in desc_lower or "command line" in desc_lower) and any(
            fw in {"Django", "FastAPI", "Express.js"} for fw in detected_frameworks
        ):
            conflict_item = {
                "type": "conflict",
                "source": f"{readme_path} vs manifests",
                "observation": (
                    f"README describes the project as a command-line tool, but dependencies "
                    f"declare full web framework(s): {', '.join(detected_frameworks)}."
                ),
                "relevance": "Conflicting purpose evidence between documentation and dependencies.",
            }
            conflicts.append(conflict_item)
            evidence.append(conflict_item)

        # Conflict check: claims no dependencies but has declared packages
        if ("no dependencies" in desc_lower or "zero-dependency" in desc_lower) and len(declared_deps) > 2:
            conflict_item = {
                "type": "conflict",
                "source": f"{readme_path} vs manifests",
                "observation": (
                    "README claims zero external dependencies, but manifest declares "
                    f"{len(declared_deps)} packages."
                ),
                "relevance": "Contradiction between claims and manifest configuration.",
            }
            conflicts.append(conflict_item)
            evidence.append(conflict_item)

    # 9. Incomplete or Uncertain Areas
    # Carry forward health findings and syntax errors
    for health_finding in dependency_res.get("findings", []):
        if health_finding["severity"] in {"error", "warning"}:
            incomplete_areas.append(
                {
                    "area": health_finding["category"],
                    "description": health_finding["description"],
                    "evidence": health_finding["evidence"],
                    "confidence": health_finding["confidence"],
                }
            )

    for code_finding in code_res.get("findings", []):
        if code_finding["type"] == "syntax_error":
            incomplete_areas.append(
                {
                    "area": "syntax_error",
                    "description": code_finding["message"],
                    "evidence": f"File '{code_finding['path']}' at line {code_finding['line']}.",
                    "confidence": "confirmed",
                }
            )

    # 10. Formulate Probable Purpose & Calibrate Confidence
    total_files = len(inventory_files)
    total_py = len(code_files)

    if total_files == 0 or (total_py == 0 and not readme_description and not detected_frameworks):
        probable_purpose = (
            "The project purpose could not be determined reliably due to insufficient documentation, "
            "lack of dependency declarations, and minimal source code."
        )
        confidence = "low"

    elif readme_description:
        if conflicts:
            probable_purpose = (
                f"Documentation indicates: '{readme_description}'. However, conflicting technical "
                f"evidence was detected in dependencies ({', '.join(detected_frameworks) or 'None'}), "
                "suggesting an unfinished migration, multi-component repository, or stale documentation."
            )
            confidence = "low"
        else:
            probable_purpose = (
                f"Based on documentation and confirmed project structure, this project is designed as: "
                f"'{readme_description}'. "
                f"Architectural pattern is characterized as {primary_pattern}."
            )
            confidence = "high" if detected_frameworks or likely_entry_points else "medium"

    elif detected_frameworks:
        frameworks_str = ", ".join(detected_frameworks)
        probable_purpose = (
            f"Inferred {primary_pattern} built with {frameworks_str}. "
            "No primary README was provided, but source structure and manifest declarations "
            "provide consistent architectural evidence."
        )
        confidence = "medium"

    elif total_py > 0:
        if total_py <= 1 and code_res.get("summary", {}).get("function_count", 0) <= 1:
            probable_purpose = (
                "The project purpose could not be determined reliably due to insufficient documentation, "
                "lack of dependency declarations, and minimal source code."
            )
            confidence = "low"
        else:
            probable_purpose = (
                f"Standalone Python utility consisting of {total_py} script(s). "
                "Purpose remains tentative due to absence of documentation and external dependency manifests."
            )
            confidence = "low"
    else:
        probable_purpose = (
            "The project purpose could not be determined reliably due to insufficient documentation, "
            "lack of dependency declarations, and minimal source code."
        )
        confidence = "low"

    limitations = [
        "Inferences are deterministic and derived from static analysis of file topology, manifests, and AST metadata.",
        "Code execution, dynamic runtime inspection, and external API queries are intentionally avoided.",
        "Semantic interpretation is strictly evidence-bounded and does not invent undocumented features.",
    ]

    return {
        "status": "success",
        "validation": validation,
        "project_name": project_name,
        "probable_purpose": probable_purpose,
        "likely_features": likely_features,
        "probable_architecture": architecture,
        "likely_entry_points": likely_entry_points,
        "incomplete_or_uncertain_areas": incomplete_areas,
        "evidence": evidence,
        "confidence": confidence,
        "limitations": limitations,
        "issues": [],
    }
