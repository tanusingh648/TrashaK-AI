"""Tests for TRASHAK AI Recovery Plan Generator."""

import pytest

from backend.ai.recovery_planner import generate_recovery_plan


# ---------------------------------------------------------------------------
# Multiple Findings with Different Priorities
# ---------------------------------------------------------------------------


def test_multiple_findings_different_priorities():
    """Verify that actions are prioritized strictly: critical -> high -> medium -> low."""
    analysis_input = {
        "status": "success",
        "probable_purpose": "REST API service for document processing.",
        "findings": [
            {
                "category": "documentation_gap",
                "description": "Project lacks a README file.",
                "evidence": "No README in archive.",
                "confidence": "confirmed",
            },
            {
                "category": "syntax_error",
                "path": "app.py",
                "line": 42,
                "message": "SyntaxError at line 42: invalid syntax",
                "evidence": "Syntax error in app.py",
            },
            {
                "category": "manifest_gap",
                "description": "No dependency manifest found.",
                "evidence": "Missing requirements.txt",
                "confidence": "confirmed",
            },
            {
                "category": "test_gap",
                "description": "No automated test files found.",
                "evidence": "0 test files in archive.",
                "confidence": "confirmed",
            },
        ],
    }

    result = generate_recovery_plan(analysis_input)
    assert result["status"] == "success"

    actions = result["actions"]
    assert len(actions) == 4

    # Verify deterministic priority ordering
    priorities = [a["priority"] for a in actions]
    assert priorities == ["critical", "high", "medium", "low"]

    # Verify summary blockers
    blockers = result["summary"]["blockers"]
    assert len(blockers) == 2  # critical and high
    assert any("Syntax Error" in b for b in blockers)
    assert any("Dependency Manifest" in b for b in blockers)

    # First recommended action should be the critical syntax fix
    assert result["summary"]["recommended_first_action"] == "ACT-01"
    assert actions[0]["category"] == "syntax"


# ---------------------------------------------------------------------------
# Confirmed Versus Uncertain Findings
# ---------------------------------------------------------------------------


def test_confirmed_versus_uncertain_findings():
    """Verify that confirmed defects have high confidence while uncertain items require human review."""
    analysis_input = {
        "status": "success",
        "findings": [
            {
                "category": "syntax_error",
                "path": "main.py",
                "line": 10,
                "description": "Syntax error in main.py",
                "confidence": "confirmed",
            },
            {
                "category": "dependency_gap",
                "description": "Possible undeclared dependency: 'redis' is imported but not declared.",
                "evidence": "Imported in worker.py line 5.",
                "confidence": "uncertain",
            },
        ],
    }

    result = generate_recovery_plan(analysis_input)
    actions = {a["category"]: a for a in result["actions"]}

    # Syntax error is confirmed
    assert actions["syntax"]["confidence"] == "high"
    assert actions["syntax"]["requires_human_review"] is False

    # Undeclared dependency is uncertain and flagged for human review
    assert actions["dependency"]["confidence"] in {"medium", "uncertain"}
    assert actions["dependency"]["requires_human_review"] is True


# ---------------------------------------------------------------------------
# Deduplication Across Modules
# ---------------------------------------------------------------------------


def test_duplicate_findings_across_modules():
    """Verify that identical findings reported by multiple submodules are deduplicated."""
    analysis_input = {
        "status": "success",
        "code_analysis": {
            "findings": [
                {
                    "type": "syntax_error",
                    "path": "broken.py",
                    "line": 15,
                    "message": "SyntaxError at line 15: unexpected EOF",
                    "evidence": "From code analyzer",
                }
            ]
        },
        "intent": {
            "incomplete_or_uncertain_areas": [
                {
                    "area": "syntax_error",
                    "path": "broken.py",
                    "line": 15,
                    "description": "SyntaxError at line 15: unexpected EOF",
                    "evidence": "From intent reconstructor",
                }
            ]
        },
    }

    result = generate_recovery_plan(analysis_input)
    actions = result["actions"]

    # Must be deduplicated into a single action
    assert len(actions) == 1
    action = actions[0]
    assert action["category"] == "syntax"
    assert "broken.py" in action["title"]

    # All evidence references should be preserved
    assert len(action["evidence_references"]) == 2
    obs = [e["observation"] for e in action["evidence_references"]]
    assert "From code analyzer" in obs
    assert "From intent reconstructor" in obs


# ---------------------------------------------------------------------------
# Evidence Reference Preservation
# ---------------------------------------------------------------------------


def test_evidence_reference_preservation():
    """Ensure every action retains its concrete evidence references."""
    analysis_input = {
        "status": "success",
        "findings": [
            {
                "category": "malformed_manifest",
                "path": "package.json",
                "description": "JSON syntax error",
                "evidence": "Unexpected token at line 3 column 5",
            }
        ],
    }

    result = generate_recovery_plan(analysis_input)
    action = result["actions"][0]

    assert len(action["evidence_references"]) >= 1
    ev = action["evidence_references"][0]
    assert ev["source"] == "package.json"
    assert "Unexpected token" in ev["observation"]


# ---------------------------------------------------------------------------
# Dependency Ordering Between Actions
# ---------------------------------------------------------------------------


def test_dependency_ordering_between_actions():
    """Verify that downstream actions record dependencies on upstream blockers."""
    analysis_input = {
        "status": "success",
        "findings": [
            {
                "category": "syntax_error",
                "path": "engine.py",
                "line": 5,
                "message": "Syntax error",
            },
            {
                "category": "manifest_gap",
                "description": "Missing requirements.txt",
            },
            {
                "category": "dependency_gap",
                "description": "Possible undeclared dependency: 'requests'",
            },
        ],
    }

    result = generate_recovery_plan(analysis_input)
    actions = {a["category"]: a for a in result["actions"]}

    syntax_id = actions["syntax"]["id"]
    manifest_id = actions["manifest"]["id"]
    dep_action = actions["dependency"]

    # Resolving undeclared dependencies depends on creating the manifest and fixing syntax
    assert syntax_id in dep_action["dependencies_on"]
    assert manifest_id in dep_action["dependencies_on"]


# ---------------------------------------------------------------------------
# Empty and Malformed Inputs
# ---------------------------------------------------------------------------


def test_empty_analysis_results():
    """Handle empty or None input gracefully without raising unhandled exceptions."""
    result_none = generate_recovery_plan(None)
    assert result_none["status"] == "error"
    assert result_none["actions"] == []
    assert len(result_none["issues"]) > 0

    result_empty = generate_recovery_plan({})
    assert result_empty["status"] == "error"
    assert result_empty["actions"] == []


def test_missing_or_malformed_fields():
    """Ensure unexpected or malformed items in findings list do not crash planner."""
    analysis_input = {
        "status": "success",
        "findings": [
            "unexpected string instead of dict",
            {"weird_format": True},
            None,
        ],
    }

    result = generate_recovery_plan(analysis_input)
    assert result["status"] == "success"
    # Does not crash, handles malformed items safely
    assert isinstance(result["actions"], list)


# ---------------------------------------------------------------------------
# No Invented Defects
# ---------------------------------------------------------------------------


def test_no_invented_defects():
    """A clean analysis report with zero findings should generate zero defect actions."""
    clean_input = {
        "status": "success",
        "probable_purpose": "Production Web Application",
        "validation": {"valid": True, "issues": []},
        "findings": [],
        "incomplete_or_uncertain_areas": [],
    }

    result = generate_recovery_plan(clean_input)
    assert result["status"] == "success"
    assert len(result["actions"]) == 0
    assert result["summary"]["total_recovery_actions"] == 0
    assert result["summary"]["blockers"] == []


# ---------------------------------------------------------------------------
# Stable Deterministic Output
# ---------------------------------------------------------------------------


def test_stable_deterministic_output():
    """Multiple runs on the same input must generate identical action IDs, titles, and order."""
    analysis_input = {
        "status": "success",
        "findings": [
            {"category": "test_gap", "description": "No tests"},
            {"category": "documentation_gap", "description": "No README"},
            {"category": "manifest_gap", "description": "No manifest"},
        ],
    }

    run1 = generate_recovery_plan(analysis_input)
    run2 = generate_recovery_plan(analysis_input)

    assert [a["id"] for a in run1["actions"]] == [a["id"] for a in run2["actions"]]
    assert [a["title"] for a in run1["actions"]] == [a["title"] for a in run2["actions"]]
    assert [a["priority"] for a in run1["actions"]] == [a["priority"] for a in run2["actions"]]


# ---------------------------------------------------------------------------
# Validation Failure Critical Blocker
# ---------------------------------------------------------------------------


def test_validation_failure_critical_blocker():
    """Ensure that validation errors are treated as critical security blockers."""
    analysis_input = {
        "status": "error",
        "validation": {
            "valid": False,
            "issues": ["Path traversal detected in entry: '../evil.py'"],
        },
    }

    result = generate_recovery_plan(analysis_input)
    actions = result["actions"]

    assert len(actions) == 1
    assert actions[0]["priority"] == "critical"
    assert actions[0]["category"] == "security"
    assert "Archive Security" in actions[0]["title"]
    assert result["summary"]["recommended_first_action"] == actions[0]["id"]
