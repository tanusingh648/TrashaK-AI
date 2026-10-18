"""TRASHAK AI - Frontend API Client and Formatting Utilities.

Provides backend API integration, health probing, archive upload orchestration,
and data extraction helpers for the Streamlit dashboard.
"""

import os
from typing import Any, Dict, List, Optional
import requests

DEFAULT_BACKEND_URL: str = "http://127.0.0.1:8000"


def get_backend_url(override_url: Optional[str] = None) -> str:
    """Retrieve and normalize backend URL from override, environment, or default."""
    if override_url and override_url.strip():
        url = override_url.strip()
    else:
        url = os.environ.get("TRASHAK_BACKEND_URL", DEFAULT_BACKEND_URL).strip()
    return url.rstrip("/")


def check_backend_health(base_url: str, timeout: float = 3.0) -> Dict[str, Any]:
    """Probe the health status of the TRASHAK AI backend service."""
    target_url = f"{get_backend_url(base_url)}/health"
    try:
        response = requests.get(target_url, timeout=timeout)
        if response.status_code == 200:
            payload = response.json()
            return {
                "online": True,
                "status": payload.get("status", "healthy"),
                "service": payload.get("service", "TRASHAK AI API"),
                "error": None,
            }
        return {
            "online": False,
            "status": "unhealthy",
            "error": f"Backend returned HTTP {response.status_code}",
        }
    except requests.exceptions.Timeout:
        return {
            "online": False,
            "status": "offline",
            "error": f"Health check timed out after {timeout}s",
        }
    except requests.exceptions.RequestException as exc:
        return {
            "online": False,
            "status": "offline",
            "error": f"Backend unreachable: {type(exc).__name__}",
        }


def analyze_project_archive(
    base_url: str,
    file_bytes: bytes,
    filename: str = "project.zip",
    timeout: float = 60.0,
) -> Dict[str, Any]:
    """Submit a project archive to POST /analyze and receive recovery report."""
    if not file_bytes:
        return {
            "success": False,
            "status_code": 400,
            "data": None,
            "error": "Uploaded file is empty (0 bytes).",
        }

    target_url = f"{get_backend_url(base_url)}/analyze"
    files = {"file": (filename, file_bytes, "application/zip")}

    try:
        response = requests.post(target_url, files=files, timeout=timeout)
        try:
            payload = response.json()
        except Exception:
            payload = {"raw_text": response.text}

        if response.status_code == 200:
            return {
                "success": True,
                "status_code": 200,
                "data": payload,
                "error": None,
            }

        # Handle 400 rejection (validation errors or bad requests)
        if response.status_code == 400:
            msg = payload.get("message") or payload.get("detail") or "Archive rejected."
            return {
                "success": False,
                "status_code": 400,
                "data": payload,
                "error": msg,
            }

        # Handle 413 file too large
        if response.status_code == 413:
            msg = payload.get("detail") or "Uploaded file exceeds maximum allowed size (25 MiB)."
            return {
                "success": False,
                "status_code": 413,
                "data": payload,
                "error": msg,
            }

        # Any other HTTP status
        detail = payload.get("detail") or f"Server returned HTTP {response.status_code}"
        return {
            "success": False,
            "status_code": response.status_code,
            "data": payload,
            "error": detail,
        }

    except requests.exceptions.Timeout:
        return {
            "success": False,
            "status_code": 0,
            "data": None,
            "error": f"Analysis request timed out after {timeout} seconds.",
        }
    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "status_code": 0,
            "data": None,
            "error": (
                f"Cannot connect to TRASHAK AI backend at {get_backend_url(base_url)}. "
                "Ensure the FastAPI service is running."
            ),
        }
    except requests.exceptions.RequestException as exc:
        return {
            "success": False,
            "status_code": 0,
            "data": None,
            "error": f"Network error during upload: {type(exc).__name__}",
        }


def format_bytes(num_bytes: int) -> str:
    """Format byte integers into human-readable binary units (KiB, MiB)."""
    if num_bytes is None or not isinstance(num_bytes, (int, float)):
        return "0 B"
    num = float(num_bytes)
    for unit in ["B", "KiB", "MiB", "GiB"]:
        if abs(num) < 1024.0:
            return f"{num:.1f} {unit}" if unit != "B" else f"{int(num)} B"
        num /= 1024.0
    return f"{num:.1f} TiB"


def extract_summary_stats(report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Safely extract high-level overview metrics from the analysis report."""
    default_stats: Dict[str, Any] = {
        "status": "unknown",
        "project_name": "Undetermined",
        "probable_purpose": "No purpose determined.",
        "confidence": "low",
        "total_files": 0,
        "total_size_bytes": 0,
        "python_files": 0,
        "dependencies_count": 0,
        "health_findings_count": 0,
        "total_recovery_actions": 0,
        "critical_actions": 0,
        "high_actions": 0,
        "medium_actions": 0,
        "low_actions": 0,
        "recommended_first_action": None,
        "blockers": [],
        "validation_valid": False,
        "validation_issues": [],
    }

    if not isinstance(report, dict) or not report:
        return default_stats

    # Extract status
    default_stats["status"] = report.get("status", "unknown")

    # Validation
    val = report.get("validation")
    if isinstance(val, dict):
        default_stats["validation_valid"] = bool(val.get("valid", False))
        default_stats["validation_issues"] = list(val.get("issues") or [])

    # Inventory
    inv = report.get("inventory")
    if isinstance(inv, dict):
        summary = inv.get("summary") or {}
        default_stats["total_files"] = summary.get("total_files", 0)
        default_stats["total_size_bytes"] = summary.get("total_size_bytes", 0)

    # Code Analysis
    code = report.get("code_analysis")
    if isinstance(code, dict):
        c_summary = code.get("summary") or {}
        default_stats["python_files"] = c_summary.get("total_python_files", 0)

    # Dependencies
    deps = report.get("dependencies")
    if isinstance(deps, dict):
        d_summary = deps.get("summary") or {}
        default_stats["dependencies_count"] = d_summary.get("dependencies_declared", 0)
        default_stats["health_findings_count"] = d_summary.get("health_findings_count", 0)

    # Intent
    intent = report.get("intent")
    if isinstance(intent, dict):
        default_stats["project_name"] = intent.get("project_name") or "Undetermined"
        default_stats["probable_purpose"] = (
            intent.get("probable_purpose") or "No purpose determined."
        )
        default_stats["confidence"] = intent.get("confidence", "low")

    # Recovery Plan
    plan = report.get("recovery_plan")
    if isinstance(plan, dict):
        p_summary = plan.get("summary") or {}
        default_stats["total_recovery_actions"] = p_summary.get("total_recovery_actions", 0)
        actions_by_p = p_summary.get("actions_by_priority") or {}
        default_stats["critical_actions"] = actions_by_p.get("critical", 0)
        default_stats["high_actions"] = actions_by_p.get("high", 0)
        default_stats["medium_actions"] = actions_by_p.get("medium", 0)
        default_stats["low_actions"] = actions_by_p.get("low", 0)
        default_stats["recommended_first_action"] = p_summary.get("recommended_first_action")
        default_stats["blockers"] = list(p_summary.get("blockers") or [])

    return default_stats
