"""TRASHAK AI - Evidence-Based Project Recovery Plan Generator.

Transforms diagnostic analysis results into a prioritized, actionable recovery plan.
Deduplicates findings, orders actions by operational urgency, preserves evidence
citations, and clearly distinguishes confirmed defects from uncertain warnings.
Never executes code, modifies files, or installs packages.
"""

import re
from typing import Any, Dict, List, Optional, Set

# Priority rank for deterministic ordering
PRIORITY_RANK: Dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def _normalize_evidence(evidence_raw: Any, default_source: str = "project") -> Dict[str, Any]:
    """Normalize evidence entry into a consistent dictionary structure."""
    if isinstance(evidence_raw, dict):
        return {
            "source": evidence_raw.get("source") or evidence_raw.get("path") or default_source,
            "observation": evidence_raw.get("observation") or evidence_raw.get("message") or evidence_raw.get("evidence") or str(evidence_raw),
            "relevance": evidence_raw.get("relevance") or "Identified diagnostic finding.",
        }
    return {
        "source": default_source,
        "observation": str(evidence_raw),
        "relevance": "Direct diagnostic observation.",
    }


def generate_recovery_plan(analysis_results: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate an evidence-based, prioritized project recovery plan.

    Args:
        analysis_results: Output from one or more TRASHAK AI analysis modules
                          (validator, inventory, code analyzer, dependency analyzer,
                          or intent reconstructor).

    Returns:
        Dict containing:
            - status (str): "success" or "error"
            - summary (dict): Purpose, counts by priority, blockers, uncertainties, first action
            - actions (list[dict]): Prioritized recovery action items
            - issues (list[str]): General planning issues or warnings
    """
    empty_summary = {
        "probable_project_purpose": None,
        "total_recovery_actions": 0,
        "actions_by_priority": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "blockers": [],
        "uncertainties": [],
        "recommended_first_action": None,
    }

    if not isinstance(analysis_results, dict) or not analysis_results:
        return {
            "status": "error",
            "summary": {
                **empty_summary,
                "uncertainties": ["Analysis results are empty or invalid; cannot formulate recovery actions."],
            },
            "actions": [],
            "issues": ["Provided analysis results were empty or not a valid dictionary."],
        }

    # Extract probable purpose if available
    probable_purpose = (
        analysis_results.get("intent", {}).get("probable_purpose")
        or analysis_results.get("probable_purpose")
    )

    validation = analysis_results.get("validation", {})
    is_valid = validation.get("valid", True) if isinstance(validation, dict) else True
    val_issues = validation.get("issues", []) if isinstance(validation, dict) else []

    # Intermediate storage for candidate actions keyed for deduplication
    candidate_actions: Dict[str, Dict[str, Any]] = {}

    # 1. Validation Failures (Critical Blockers)
    if not is_valid and val_issues:
        for idx, issue in enumerate(val_issues):
            key = f"validation_failure_{idx}"
            candidate_actions[key] = {
                "title": f"Resolve Archive Security / Integrity Violation: {issue[:60]}",
                "description": f"The project archive failed security or format validation: {issue}.",
                "priority": "critical",
                "category": "security",
                "rationale": "Archive security and format integrity must be satisfied before files can be inspected or executed.",
                "evidence_references": [{"source": "archive_validator", "observation": issue, "relevance": "Validation blocker"}],
                "confidence": "high",
                "suggested_steps": [
                    "Inspect the ZIP archive structure using standard inspection tools.",
                    "Ensure the archive does not contain path traversals, encrypted entries, or excessive compression ratios.",
                    "Re-package the project into a clean, uncorrupted ZIP archive.",
                ],
                "requires_human_review": False,
            }

    # Helper to ingest findings from any module
    def ingest_finding(finding: Dict[str, Any], default_source: str = "scanner"):
        f_type = finding.get("category") or finding.get("type") or finding.get("area") or "general"
        f_desc = finding.get("description") or finding.get("message") or ""
        f_path = finding.get("path") or finding.get("source") or default_source
        f_ev = finding.get("evidence") or f_desc
        f_conf = finding.get("confidence") or "high"
        f_line = finding.get("line")

        if not finding.get("path") and isinstance(f_ev, str):
            match_path = re.search(r"File '([^']+)'(?: at line (\d+))?", f_ev)
            if match_path:
                f_path = match_path.group(1)
                if match_path.group(2) and not f_line:
                    f_line = int(match_path.group(2))

        # Deduplication keys & mapping
        if f_type in {"syntax_error", "read_error"}:
            key = f"syntax_{f_path}_{f_line}"
            ev_ref = _normalize_evidence(f_ev, f_path)
            if key in candidate_actions:
                candidate_actions[key]["evidence_references"].append(ev_ref)
                return

            line_str = f" at line {f_line}" if f_line else ""
            candidate_actions[key] = {
                "title": f"Fix Syntax Error in '{f_path}'{line_str}",
                "description": f"Python syntax error prevents module compilation: {f_desc}.",
                "priority": "critical",
                "category": "syntax",
                "rationale": f"Syntax errors in '{f_path}' prevent the application from running or being tested.",
                "evidence_references": [ev_ref],
                "confidence": "high",
                "suggested_steps": [
                    f"Open '{f_path}'{line_str}.",
                    "Correct the malformed syntax construct (e.g. missing colon, mismatched brackets, or invalid syntax).",
                    f"Validate syntax using Python AST compiler: python -m py_compile {f_path}.",
                ],
                "requires_human_review": False,
            }

        elif f_type == "malformed_manifest":
            key = f"malformed_manifest_{f_path}"
            ev_ref = _normalize_evidence(f_ev, f_path)
            if key in candidate_actions:
                candidate_actions[key]["evidence_references"].append(ev_ref)
                return

            candidate_actions[key] = {
                "title": f"Repair Malformed Dependency Manifest '{f_path}'",
                "description": f"Dependency manifest cannot be parsed: {f_desc}.",
                "priority": "high",
                "category": "manifest",
                "rationale": f"Corrupted manifest '{f_path}' prevents dependency installation and environment setup.",
                "evidence_references": [ev_ref],
                "confidence": "high",
                "suggested_steps": [
                    f"Open '{f_path}' in an editor.",
                    "Validate and correct format syntax errors (JSON, TOML, or requirements format).",
                    "Verify the manifest using language packaging tools.",
                ],
                "requires_human_review": False,
            }

        elif f_type == "manifest_gap":
            key = "manifest_gap"
            ev_ref = _normalize_evidence(f_ev, "manifests")
            if key in candidate_actions:
                candidate_actions[key]["evidence_references"].append(ev_ref)
                return

            candidate_actions[key] = {
                "title": "Create Project Dependency Manifest",
                "description": "Project contains source code but lacks a standard dependency specification.",
                "priority": "high",
                "category": "manifest",
                "rationale": "Without a declared dependency manifest, third-party libraries cannot be installed reliably.",
                "evidence_references": [ev_ref],
                "confidence": "high",
                "suggested_steps": [
                    "Identify third-party libraries imported across project source files.",
                    "Create requirements.txt (or pyproject.toml / package.json as appropriate).",
                    "Pin compatible version constraints for all required packages.",
                ],
                "requires_human_review": False,
            }

        elif f_type == "possible_unresolved_local_import":
            mod_target = finding.get("import") or f_desc
            key = f"unresolved_import_{f_path}_{mod_target}"
            ev_ref = _normalize_evidence(f_ev, f_path)
            if key in candidate_actions:
                candidate_actions[key]["evidence_references"].append(ev_ref)
                return

            candidate_actions[key] = {
                "title": f"Resolve Missing Local Module for '{f_path}'",
                "description": f"Local import target not found in project: {f_desc}.",
                "priority": "high",
                "category": "code_structure",
                "rationale": f"Missing local module imported by '{f_path}' will cause an ImportError at runtime.",
                "evidence_references": [ev_ref],
                "confidence": "high",
                "suggested_steps": [
                    f"Check '{f_path}' to see if the target module was renamed or omitted.",
                    "Re-create the missing module or update the import path to an existing file.",
                    "Verify that local directory packages contain an __init__.py file.",
                ],
                "requires_human_review": False,
            }

        elif f_type == "dependency_gap":
            # Extract module name from description or evidence
            match = re.search(r"'([a-zA-Z0-9_\-\.]+)'", f_desc)
            mod_name = match.group(1) if match else "unknown"
            key = f"dependency_gap_{mod_name.lower()}"
            ev_ref = _normalize_evidence(f_ev, "imports")
            if key in candidate_actions:
                candidate_actions[key]["evidence_references"].append(ev_ref)
                return

            candidate_actions[key] = {
                "title": f"Verify Undeclared Dependency '{mod_name}'",
                "description": f"Module '{mod_name}' is imported but was not found in declared dependency manifests.",
                "priority": "medium",
                "category": "dependency",
                "rationale": f"Importing undeclared module '{mod_name}' may cause ModuleNotFoundError in fresh environments.",
                "evidence_references": [ev_ref],
                "confidence": f_conf,
                "suggested_steps": [
                    f"Confirm whether '{mod_name}' is an external package required by the project.",
                    f"Add '{mod_name}' with version constraints to requirements.txt or pyproject.toml.",
                    "Test importing the package in a clean virtual environment.",
                ],
                "requires_human_review": True,
            }

        elif f_type == "entry_point_gap":
            key = "entry_point_gap"
            ev_ref = _normalize_evidence(f_ev, "code_analyzer")
            if key in candidate_actions:
                candidate_actions[key]["evidence_references"].append(ev_ref)
                return

            candidate_actions[key] = {
                "title": "Define Application Execution Entry Point",
                "description": "No standard execution entry point (e.g. main.py, app.py, or main guard) was identified.",
                "priority": "medium",
                "category": "entry_point",
                "rationale": "Users and automated runners need an unambiguous command or script to launch the application.",
                "evidence_references": [ev_ref],
                "confidence": "medium",
                "suggested_steps": [
                    "Identify the primary module intended to run the application.",
                    "Add an if __name__ == '__main__': entry guard or entry function.",
                    "Document the startup command in README.",
                ],
                "requires_human_review": True,
            }

        elif f_type == "test_gap":
            key = "test_gap"
            ev_ref = _normalize_evidence(f_ev, "inventory")
            if key in candidate_actions:
                candidate_actions[key]["evidence_references"].append(ev_ref)
                return

            candidate_actions[key] = {
                "title": "Establish Automated Test Suite",
                "description": "The project lacks automated tests or a conventional test directory.",
                "priority": "medium",
                "category": "test",
                "rationale": "Automated regression tests are required to safely refactor and verify project behavior.",
                "evidence_references": [ev_ref],
                "confidence": "high",
                "suggested_steps": [
                    "Create a tests/ directory in the project root.",
                    "Add an initial test file (e.g. tests/test_smoke.py) verifying core module imports.",
                    "Configure pytest as the automated test runner.",
                ],
                "requires_human_review": False,
            }

        elif f_type == "documentation_gap":
            key = "documentation_gap"
            ev_ref = _normalize_evidence(f_ev, "inventory")
            if key in candidate_actions:
                candidate_actions[key]["evidence_references"].append(ev_ref)
                return

            candidate_actions[key] = {
                "title": "Create Project Documentation (README)",
                "description": "Project lacks a README or overview documentation file.",
                "priority": "low",
                "category": "documentation",
                "rationale": "Clear documentation is essential for onboarding, setup, and recovery guidance.",
                "evidence_references": [ev_ref],
                "confidence": "high",
                "suggested_steps": [
                    "Create a README.md file in the project root.",
                    "Document project purpose, prerequisites, installation steps, and usage examples.",
                ],
                "requires_human_review": False,
            }

        elif f_type == "configuration_gap":
            key = "configuration_gap"
            ev_ref = _normalize_evidence(f_ev, "inventory")
            if key in candidate_actions:
                candidate_actions[key]["evidence_references"].append(ev_ref)
                return

            candidate_actions[key] = {
                "title": "Add .gitignore File",
                "description": "Project lacks a .gitignore file.",
                "priority": "low",
                "category": "configuration",
                "rationale": "Prevents accidental versioning of virtual environments, bytecode caches, and sensitive files.",
                "evidence_references": [ev_ref],
                "confidence": "high",
                "suggested_steps": [
                    "Create a .gitignore file in the project root.",
                    "Exclude .venv/, __pycache__/, .env, build/, and test cache artifacts.",
                ],
                "requires_human_review": False,
            }

        elif f_type == "conflict":
            key = f"conflict_{f_path}"
            ev_ref = _normalize_evidence(f_ev, f_path)
            if key in candidate_actions:
                candidate_actions[key]["evidence_references"].append(ev_ref)
                return

            candidate_actions[key] = {
                "title": "Reconcile Documentation and Architecture Conflict",
                "description": f"Discrepancy detected between documentation claims and codebase implementation: {f_desc}.",
                "priority": "medium",
                "category": "documentation",
                "rationale": "Conflicting purpose statements cause confusion during recovery and development.",
                "evidence_references": [ev_ref],
                "confidence": "medium",
                "suggested_steps": [
                    "Determine whether the project was repurposed or migrated to a different architecture.",
                    "Update documentation or codebase configuration to establish consistency.",
                ],
                "requires_human_review": True,
            }

    # Ingest findings from all available nested or top-level analysis sources
    for source_key in ("findings", "incomplete_or_uncertain_areas"):
        for item in analysis_results.get(source_key, []):
            if isinstance(item, dict):
                ingest_finding(item)

    for sub_module in ("code_analysis", "dependencies", "intent"):
        sub_dict = analysis_results.get(sub_module, {})
        if isinstance(sub_dict, dict):
            for item in sub_dict.get("findings", []):
                if isinstance(item, dict):
                    ingest_finding(item, default_source=sub_module)
            for item in sub_dict.get("incomplete_or_uncertain_areas", []):
                if isinstance(item, dict):
                    ingest_finding(item, default_source=sub_module)
            for item in sub_dict.get("evidence", []):
                if isinstance(item, dict) and item.get("type") == "conflict":
                    ingest_finding(item, default_source=sub_module)

    # Convert candidate actions to list and sort deterministically
    actions_list = list(candidate_actions.values())

    # Sort deterministically by:
    # 1. Priority rank (critical=0, high=1, medium=2, low=3)
    # 2. Category
    # 3. Title
    actions_list.sort(
        key=lambda a: (
            PRIORITY_RANK.get(a["priority"], 99),
            a["category"],
            a["title"],
        )
    )

    # Assign sequential Action IDs (ACT-01, ACT-02, ...)
    for idx, act in enumerate(actions_list, start=1):
        act["id"] = f"ACT-{idx:02d}"

    # Establish dependencies between recovery actions
    # Rule 1: Critical syntax or security fixes block downstream actions
    syntax_or_sec_ids = [
        a["id"] for a in actions_list if a["category"] in {"security", "syntax"}
    ]
    manifest_ids = [
        a["id"] for a in actions_list if a["category"] == "manifest"
    ]

    for act in actions_list:
        deps_on: List[str] = []
        if act["category"] not in {"security", "syntax"}:
            deps_on.extend(syntax_or_sec_ids)

        if act["category"] == "dependency" and manifest_ids:
            # Adding/verifying undeclared dependencies depends on creating the manifest
            deps_on.extend(manifest_ids)

        if act["category"] == "test" and (syntax_or_sec_ids or manifest_ids):
            deps_on.extend(manifest_ids)

        # Deduplicate and exclude self-dependency
        act["dependencies_on"] = sorted(list(set(d for d in deps_on if d != act["id"])))

    # Compute summary metrics
    actions_by_priority = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    blockers: List[str] = []
    uncertainties: List[str] = []

    for act in actions_list:
        p = act["priority"]
        actions_by_priority[p] = actions_by_priority.get(p, 0) + 1

        if p in {"critical", "high"}:
            blockers.append(f"{act['id']}: {act['title']}")

        if act["requires_human_review"] or act["confidence"] in {"low", "medium"}:
            uncertainties.append(f"{act['id']}: {act['title']}")

    recommended_first_action = actions_list[0]["id"] if actions_list else None

    summary = {
        "probable_project_purpose": probable_purpose,
        "total_recovery_actions": len(actions_list),
        "actions_by_priority": actions_by_priority,
        "blockers": blockers,
        "uncertainties": uncertainties,
        "recommended_first_action": recommended_first_action,
    }

    issues: List[str] = []
    if not actions_list:
        issues.append("No recovery actions generated. Analysis results contained no actionable defects or gaps.")

    return {
        "status": "success",
        "summary": summary,
        "actions": actions_list,
        "issues": issues,
    }
