"""Tests for TRASHAK AI Evidence-Based Project Intent Reconstructor."""

import io
import zipfile
import pytest

from backend.ai.intent_reconstructor import reconstruct_intent


def _create_zip(entries: dict) -> bytes:
    """Helper to build an in-memory ZIP archive from a dict of {path: content_bytes}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, content in entries.items():
            zf.writestr(path, content)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Project with Descriptive README
# ---------------------------------------------------------------------------


def test_project_with_descriptive_readme():
    """Verify high-confidence intent extraction when a clear README and matching code exist."""
    readme_content = b"""# PDFForge CLI

A high-performance command-line utility to merge, split, and watermark PDF documents.

## Features
- Fast multi-file PDF merging
- Dynamic page watermarking
- Document encryption and password protection

## Usage
Run python cli.py --help
"""
    cli_code = b"""import click

@click.command()
def main():
    print("PDFForge CLI")

if __name__ == "__main__":
    main()
"""
    entries = {
        "README.md": readme_content,
        "requirements.txt": b"click>=8.0\npypdf>=3.0\n",
        "cli.py": cli_code,
        "tests/test_cli.py": b"def test_main(): pass",
        ".gitignore": b".venv/\n",
    }
    archive_data = _create_zip(entries)
    result = reconstruct_intent(archive_data)

    assert result["status"] == "success"
    assert result["validation"]["valid"] is True
    assert result["project_name"] == "PDFForge CLI"
    assert "merge, split, and watermark PDF documents" in result["probable_purpose"]
    assert result["confidence"] == "high"

    # Likely features should include extracted bullet points
    feat_names = [f["name"] for f in result["likely_features"]]
    assert any("PDF merging" in f for f in feat_names)
    assert any("watermarking" in f for f in feat_names)

    # Architecture should identify CLI and Click
    arch = result["probable_architecture"]
    assert "CLI" in arch["pattern"]
    assert "Click" in arch["frameworks"]

    # Entry points
    entry_paths = [e["path"] for e in result["likely_entry_points"]]
    assert "cli.py" in entry_paths


# ---------------------------------------------------------------------------
# Project with Source Code but No README
# ---------------------------------------------------------------------------


def test_project_with_source_code_no_readme():
    """Verify inference of Web API purpose from dependencies and code when README is absent."""
    api_code = b"""from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}
"""
    entries = {
        "backend/main.py": api_code,
        "requirements.txt": b"fastapi==0.100.0\nuvicorn==0.22.0\n",
        "tests/test_api.py": b"def test_health(): pass",
        ".gitignore": b".venv/\n",
    }
    archive_data = _create_zip(entries)
    result = reconstruct_intent(archive_data)

    assert result["status"] == "success"
    assert result["confidence"] == "medium"
    assert "FastAPI" in result["probable_purpose"]
    assert "FastAPI" in result["probable_architecture"]["frameworks"]

    # Incomplete areas should highlight missing README documentation gap
    inc_areas = [a["area"] for a in result["incomplete_or_uncertain_areas"]]
    assert "documentation_gap" in inc_areas


# ---------------------------------------------------------------------------
# Project with Conflicting Evidence
# ---------------------------------------------------------------------------


def test_project_with_conflicting_evidence():
    """Detect and flag contradictions between documentation claims and declared dependencies."""
    readme_content = b"""# TinyMath

A simple standalone command-line calculator with no external dependencies.
"""
    manage_code = b"""import django
def run(): pass
"""
    entries = {
        "README.md": readme_content,
        "requirements.txt": b"django>=4.0\ncelery>=5.0\nredis>=4.0\n",
        "manage.py": manage_code,
        ".gitignore": b".venv/",
    }
    archive_data = _create_zip(entries)
    result = reconstruct_intent(archive_data)

    assert result["status"] == "success"
    # Conflicts should be detected in evidence
    conflict_evidence = [e for e in result["evidence"] if e["type"] == "conflict"]
    assert len(conflict_evidence) > 0

    conflict_texts = " ".join(e["observation"] for e in conflict_evidence)
    assert "command-line" in conflict_texts or "dependencies" in conflict_texts
    assert "Django" in conflict_texts or "django" in conflict_texts

    assert result["confidence"] == "low"
    assert "conflicting" in result["probable_purpose"].lower()


# ---------------------------------------------------------------------------
# Empty and Invalid ZIP Handling
# ---------------------------------------------------------------------------


def test_empty_valid_zip():
    """Reject empty ZIP archives cleanly without attempting reconstruction."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        pass
    empty_zip = buf.getvalue()

    result = reconstruct_intent(empty_zip)
    assert result["status"] == "error"
    assert result["validation"]["valid"] is False
    assert result["confidence"] == "low"
    assert "failed" in result["probable_purpose"].lower()


def test_invalid_and_unsafe_zip_input():
    """Reject corrupted payloads and directory traversal attempts safely."""
    bad_result = reconstruct_intent(b"corrupted-byte-payload")
    assert bad_result["status"] == "error"
    assert bad_result["validation"]["valid"] is False

    unsafe_zip = _create_zip({"../evil.py": b"print('traversal')"})
    unsafe_result = reconstruct_intent(unsafe_zip)
    assert unsafe_result["status"] == "error"
    assert unsafe_result["validation"]["valid"] is False


# ---------------------------------------------------------------------------
# Malformed Text Encoding
# ---------------------------------------------------------------------------


def test_malformed_text_encoding():
    """Ensure non-UTF8 documentation bytes are decoded using fallback without crashing."""
    # Latin-1 encoded accented title
    non_utf8_readme = b"# Outil M\xe9tier\n\nApplication de gestion pour entreprises.\n"
    entries = {
        "README.md": non_utf8_readme,
        "app.py": b"print('hello')",
    }
    archive_data = _create_zip(entries)
    result = reconstruct_intent(archive_data)

    assert result["status"] == "success"
    assert result["project_name"] is not None
    assert "Outil" in result["project_name"]


# ---------------------------------------------------------------------------
# Evidence Citations with Correct File Paths
# ---------------------------------------------------------------------------


def test_evidence_citations_with_correct_file_paths():
    """Verify that every cited piece of evidence references an actual file path."""
    entries = {
        "README.md": b"# AnalyzerTool\nAutomated static inspection tool.",
        "requirements.txt": b"pytest\n",
        "scanner.py": b"def scan(): pass\nif __name__ == '__main__': scan()",
    }
    archive_data = _create_zip(entries)
    result = reconstruct_intent(archive_data)

    assert result["status"] == "success"
    assert len(result["evidence"]) > 0

    actual_paths = set(entries.keys())
    for item in result["evidence"]:
        assert "type" in item
        assert item["type"] in {"fact", "inference", "conflict"}
        assert "source" in item
        assert "observation" in item
        assert "relevance" in item
        # If source is a file path, it should be in the archive or a known virtual category
        if "/" in item["source"] or "." in item["source"]:
            sources = item["source"].split(" vs ")
            for src in sources:
                if src not in {"dependencies", "file_topology"}:
                    assert src in actual_paths


# ---------------------------------------------------------------------------
# Uncertain Conclusions When Evidence is Weak
# ---------------------------------------------------------------------------


def test_uncertain_conclusions_when_evidence_is_weak():
    """Explicitly state purpose could not be determined reliably when evidence is insufficient."""
    # Only a single trivial variable assignment, no readme, no manifest
    entries = {
        "scratch.py": b"x = 10\n",
    }
    archive_data = _create_zip(entries)
    result = reconstruct_intent(archive_data)

    assert result["status"] == "success"
    assert result["confidence"] == "low"
    assert "could not be determined reliably" in result["probable_purpose"].lower()


# ---------------------------------------------------------------------------
# No Code Execution
# ---------------------------------------------------------------------------


def test_no_execution_of_uploaded_code(tmp_path, monkeypatch):
    """Ensure uploaded code containing harmful statements is never executed."""
    monkeypatch.chdir(tmp_path)
    # If this code were executed or imported, it would raise a RuntimeError
    malicious_code = b"""raise RuntimeError('Code execution was triggered unexpectedly!')
"""
    entries = {
        "bomb.py": malicious_code,
        "README.md": b"# Safe Project",
    }
    archive_data = _create_zip(entries)

    # Must complete safely without raising RuntimeError
    result = reconstruct_intent(archive_data)
    assert result["status"] == "success"
    # Ensure zero files written to disk
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# Integration with Existing Analyzer Schemas
# ---------------------------------------------------------------------------


def test_integration_with_existing_analyzer_schemas():
    """Verify that reconstruct_intent returns all expected top-level schema keys."""
    entries = {
        "backend/main.py": b"from fastapi import FastAPI\napp = FastAPI()",
        "requirements.txt": b"fastapi\nuvicorn\n",
        "README.md": b"# Full Project\nComprehensive description.",
        "tests/test_main.py": b"def test_app(): pass",
        ".gitignore": b".venv/\n",
    }
    archive_data = _create_zip(entries)
    result = reconstruct_intent(archive_data)

    expected_keys = {
        "status",
        "validation",
        "project_name",
        "probable_purpose",
        "likely_features",
        "probable_architecture",
        "likely_entry_points",
        "incomplete_or_uncertain_areas",
        "evidence",
        "confidence",
        "limitations",
        "issues",
    }
    assert expected_keys.issubset(result.keys())
    assert result["validation"]["valid"] is True
    assert isinstance(result["likely_features"], list)
    assert isinstance(result["probable_architecture"], dict)
    assert isinstance(result["likely_entry_points"], list)
    assert isinstance(result["incomplete_or_uncertain_areas"], list)
    assert isinstance(result["evidence"], list)
    assert isinstance(result["limitations"], list)
