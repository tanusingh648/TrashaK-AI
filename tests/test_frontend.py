"""Unit tests for TRASHAK AI frontend utilities and API client.

Validates URL resolution, byte formatting, data extraction, and HTTP error handling
without requiring a live backend service or graphical Streamlit server.
"""

from unittest.mock import MagicMock, patch
import pytest
import requests

from frontend.api_client import (
    analyze_project_archive,
    check_backend_health,
    extract_summary_stats,
    format_bytes,
    get_backend_url,
)


def test_get_backend_url_defaults(monkeypatch):
    """Verify default backend URL and env var resolution."""
    monkeypatch.delenv("TRASHAK_BACKEND_URL", raising=False)
    assert get_backend_url() == "http://127.0.0.1:8000"

    monkeypatch.setenv("TRASHAK_BACKEND_URL", "http://custom-host:9000/")
    assert get_backend_url() == "http://custom-host:9000"

    # Direct override takes precedence
    assert get_backend_url("http://override-host:8080/") == "http://override-host:8080"


def test_format_bytes():
    """Verify human-readable binary byte formatting."""
    assert format_bytes(0) == "0 B"
    assert format_bytes(512) == "512 B"
    assert format_bytes(1024) == "1.0 KiB"
    assert format_bytes(1024 * 1024 * 5) == "5.0 MiB"
    assert format_bytes(1024 * 1024 * 1024 * 2) == "2.0 GiB"
    assert format_bytes(None) == "0 B"
    assert format_bytes("invalid") == "0 B"


def test_extract_summary_stats_empty_and_none():
    """Verify graceful handling of empty or None report payloads."""
    empty_stats = extract_summary_stats(None)
    assert empty_stats["status"] == "unknown"
    assert empty_stats["total_files"] == 0
    assert empty_stats["validation_valid"] is False

    empty_dict_stats = extract_summary_stats({})
    assert empty_dict_stats["status"] == "unknown"
    assert empty_dict_stats["probable_purpose"] == "No purpose determined."


def test_extract_summary_stats_full_payload():
    """Verify proper metric extraction from a full analysis payload."""
    payload = {
        "status": "success",
        "validation": {"valid": True, "issues": []},
        "inventory": {
            "summary": {"total_files": 12, "total_size_bytes": 45000}
        },
        "code_analysis": {
            "summary": {"total_python_files": 4}
        },
        "dependencies": {
            "summary": {"dependencies_declared": 8, "health_findings_count": 2}
        },
        "intent": {
            "project_name": "DemoApp",
            "probable_purpose": "FastAPI Web Service",
            "confidence": "high",
        },
        "recovery_plan": {
            "summary": {
                "total_recovery_actions": 3,
                "actions_by_priority": {"critical": 1, "high": 1, "medium": 1, "low": 0},
                "recommended_first_action": "Fix critical blocker",
                "blockers": ["Syntax error in main.py"],
            }
        },
    }

    stats = extract_summary_stats(payload)
    assert stats["status"] == "success"
    assert stats["validation_valid"] is True
    assert stats["project_name"] == "DemoApp"
    assert stats["total_files"] == 12
    assert stats["python_files"] == 4
    assert stats["dependencies_count"] == 8
    assert stats["health_findings_count"] == 2
    assert stats["total_recovery_actions"] == 3
    assert stats["critical_actions"] == 1
    assert stats["recommended_first_action"] == "Fix critical blocker"
    assert stats["blockers"] == ["Syntax error in main.py"]


def test_extract_summary_stats_rejected_payload():
    """Verify extraction when an archive is rejected with None sub-modules."""
    payload = {
        "status": "rejected",
        "validation": {
            "valid": False,
            "issues": ["Suspicious path traversal detected: ../evil.py"],
        },
        "inventory": None,
        "code_analysis": None,
        "dependencies": None,
        "intent": None,
        "recovery_plan": {
            "summary": {
                "total_recovery_actions": 1,
                "actions_by_priority": {"critical": 1, "high": 0, "medium": 0, "low": 0},
                "recommended_first_action": "Remediate archive security violations",
                "blockers": ["Archive validation failure"],
            }
        },
    }

    stats = extract_summary_stats(payload)
    assert stats["status"] == "rejected"
    assert stats["validation_valid"] is False
    assert len(stats["validation_issues"]) == 1
    assert stats["total_files"] == 0
    assert stats["critical_actions"] == 1
    assert stats["blockers"] == ["Archive validation failure"]


def test_analyze_empty_file_bytes():
    """Verify client rejects empty file bytes without sending network request."""
    result = analyze_project_archive("http://127.0.0.1:8000", b"", "empty.zip")
    assert result["success"] is False
    assert result["status_code"] == 400
    assert "empty" in result["error"].lower()


@patch("frontend.api_client.requests.get")
def test_check_backend_health_online(mock_get):
    """Verify health check handling when backend is online."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "healthy", "service": "TRASHAK AI API"}
    mock_get.return_value = mock_resp

    health = check_backend_health("http://127.0.0.1:8000")
    assert health["online"] is True
    assert health["status"] == "healthy"
    assert health["error"] is None


@patch("frontend.api_client.requests.get")
def test_check_backend_health_offline(mock_get):
    """Verify health check handling when backend is offline."""
    mock_get.side_effect = requests.exceptions.ConnectionError("Connection refused")

    health = check_backend_health("http://127.0.0.1:8000")
    assert health["online"] is False
    assert health["status"] == "offline"
    assert "unreachable" in health["error"].lower()


@patch("frontend.api_client.requests.post")
def test_analyze_project_archive_success(mock_post):
    """Verify successful upload response parsing."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "success", "project_name": "Test"}
    mock_post.return_value = mock_resp

    res = analyze_project_archive("http://127.0.0.1:8000", b"PK\x03\x04test", "test.zip")
    assert res["success"] is True
    assert res["status_code"] == 200
    assert res["data"]["status"] == "success"


@patch("frontend.api_client.requests.post")
def test_analyze_project_archive_oversized(mock_post):
    """Verify HTTP 413 file-too-large handling."""
    mock_resp = MagicMock()
    mock_resp.status_code = 413
    mock_resp.json.return_value = {"detail": "Uploaded file exceeds maximum allowed size."}
    mock_post.return_value = mock_resp

    res = analyze_project_archive("http://127.0.0.1:8000", b"big_data", "big.zip")
    assert res["success"] is False
    assert res["status_code"] == 413
    assert "exceeds" in res["error"].lower()


@patch("frontend.api_client.requests.post")
def test_analyze_project_archive_connection_error(mock_post):
    """Verify graceful handling when backend is down during upload."""
    mock_post.side_effect = requests.exceptions.ConnectionError("Connection refused")

    res = analyze_project_archive("http://127.0.0.1:8000", b"data", "test.zip")
    assert res["success"] is False
    assert res["status_code"] == 0
    assert "cannot connect" in res["error"].lower()
