"""Tests for TRASHAK AI FastAPI Endpoints and Pipeline Integration."""

import asyncio
import io
import json
import zipfile
import pytest
from fastapi import HTTPException, UploadFile

from backend.main import (
    MAX_UPLOAD_SIZE,
    analyze_project,
    app,
    health_check,
    read_root,
)


def _create_zip(entries: dict) -> bytes:
    """Helper to build an in-memory ZIP archive from a dict of {path: content_bytes}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, content in entries.items():
            zf.writestr(path, content)
    return buf.getvalue()


async def _asgi_get(path: str) -> dict:
    """Helper to perform an ASGI GET request on the FastAPI app without external dependencies."""
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(b"host", b"testserver")],
    }
    response_meta = {}
    response_body = bytearray()

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            response_meta["status"] = message["status"]
            response_meta["headers"] = dict(message.get("headers", []))
        elif message["type"] == "http.response.body":
            response_body.extend(message.get("body", b""))

    await app(scope, receive, send)
    return {
        "status_code": response_meta.get("status"),
        "body": bytes(response_body),
        "json": json.loads(response_body.decode()) if response_body else None,
    }


# ---------------------------------------------------------------------------
# Basic Endpoint Tests (GET / and GET /health)
# ---------------------------------------------------------------------------


def test_root_endpoint_direct():
    """Verify service information returned by the root endpoint."""
    res = read_root()
    assert res["project"] == "TRASHAK AI"
    assert res["status"] == "online"
    assert "endpoints" in res


def test_health_endpoint_direct():
    """Verify health endpoint response."""
    res = health_check()
    assert res["status"] == "healthy"


def test_root_and_health_via_asgi():
    """Verify GET / and GET /health over ASGI interface using asyncio.run."""
    root_res = asyncio.run(_asgi_get("/"))
    assert root_res["status_code"] == 200
    assert root_res["json"]["project"] == "TRASHAK AI"

    health_res = asyncio.run(_asgi_get("/health"))
    assert health_res["status_code"] == 200
    assert health_res["json"]["status"] == "healthy"


# ---------------------------------------------------------------------------
# Successful Upload and Consolidated Pipeline Integration
# ---------------------------------------------------------------------------


def test_successful_upload_and_pipeline_integration():
    """Verify end-to-end execution of all 6 pipeline modules via POST /analyze."""
    entries = {
        "README.md": b"# SampleApp\nA clean test project.\n\n## Features\n- Fast execution",
        "requirements.txt": b"fastapi>=0.100\nuvicorn\n",
        "main.py": b"""from fastapi import FastAPI
app = FastAPI()

@app.get("/items")
def list_items():
    return [1, 2, 3]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app)
""",
        "tests/test_main.py": b"def test_pass(): pass",
        ".gitignore": b".venv/\n",
    }
    archive_data = _create_zip(entries)
    upload = UploadFile(filename="sample_project.zip", file=io.BytesIO(archive_data))

    response = asyncio.run(analyze_project(file=upload))
    assert response.status_code == 200

    payload = json.loads(response.body.decode())
    assert payload["status"] == "success"

    # 1. Validation block
    assert payload["validation"]["valid"] is True
    assert payload["validation"]["file_count"] >= 4

    # 2. Inventory block
    assert payload["inventory"]["status"] == "success"
    assert payload["inventory"]["summary"]["total_files"] == 5

    # 3. Code analysis block
    assert payload["code_analysis"]["status"] == "success"
    assert payload["code_analysis"]["summary"]["total_python_files"] == 2
    assert "main.py" in payload["code_analysis"]["summary"]["entry_point_candidates"]

    # 4. Dependency analysis block
    assert payload["dependencies"]["status"] == "success"
    dep_names = {d["name"] for d in payload["dependencies"]["dependencies"]}
    assert "fastapi" in dep_names
    assert "uvicorn" in dep_names

    # 5. Intent reconstruction block
    assert payload["intent"]["status"] == "success"
    assert payload["intent"]["project_name"] == "SampleApp"
    assert "FastAPI" in payload["intent"]["probable_architecture"]["frameworks"]

    # 6. Recovery plan block
    assert payload["recovery_plan"]["status"] == "success"
    assert isinstance(payload["recovery_plan"]["actions"], list)


# ---------------------------------------------------------------------------
# Upload Validation and Rejection Cases
# ---------------------------------------------------------------------------


def test_missing_or_empty_upload():
    """Reject requests with missing filename or 0-byte content."""
    # Missing filename
    with pytest.raises(HTTPException) as exc1:
        asyncio.run(analyze_project(file=UploadFile(filename="", file=io.BytesIO(b""))))
    assert exc1.value.status_code == 400

    # Non-ZIP extension
    with pytest.raises(HTTPException) as exc2:
        asyncio.run(analyze_project(file=UploadFile(filename="project.tar.gz", file=io.BytesIO(b"123"))))
    assert exc2.value.status_code == 400
    assert "ZIP" in exc2.value.detail

    # 0 bytes
    with pytest.raises(HTTPException) as exc3:
        asyncio.run(analyze_project(file=UploadFile(filename="empty.zip", file=io.BytesIO(b""))))
    assert exc3.value.status_code == 400
    assert "0 bytes" in exc3.value.detail


def test_invalid_zip_bytes():
    """Return 400 with structured validation issues for corrupted ZIP bytes."""
    corrupted_data = b"PK\x03\x04corrupted_payload_that_is_not_valid_zip"
    upload = UploadFile(filename="corrupt.zip", file=io.BytesIO(corrupted_data))

    response = asyncio.run(analyze_project(file=upload))
    assert response.status_code == 400

    payload = json.loads(response.body.decode())
    assert payload["status"] == "rejected"
    assert payload["validation"]["valid"] is False
    assert len(payload["validation"]["issues"]) > 0


def test_unsafe_zip_rejection():
    """Reject archives attempting path traversal with HTTP 400 and structured issues."""
    unsafe_data = _create_zip({"../escaped.py": b"malicious code"})
    upload = UploadFile(filename="traversal.zip", file=io.BytesIO(unsafe_data))

    response = asyncio.run(analyze_project(file=upload))
    assert response.status_code == 400

    payload = json.loads(response.body.decode())
    assert payload["status"] == "rejected"
    assert payload["validation"]["valid"] is False
    assert any("traversal" in issue.lower() for issue in payload["validation"]["issues"])


def test_oversized_upload_rejection(monkeypatch):
    """Reject files exceeding the configured compressed size limit with HTTP 413."""
    # Test with monkeypatched small limit of 500 bytes to test the stream cutoff
    monkeypatch.setattr("backend.main.MAX_UPLOAD_SIZE", 500)
    monkeypatch.setattr("backend.main.CHUNK_SIZE", 100)

    large_payload = b"A" * 600
    upload = UploadFile(filename="huge.zip", file=io.BytesIO(large_payload))

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(analyze_project(file=upload))

    assert exc_info.value.status_code == 413
    assert "maximum allowed size" in exc_info.value.detail


# ---------------------------------------------------------------------------
# Error Handling and Security Assurances
# ---------------------------------------------------------------------------


def test_no_traceback_exposure_on_errors():
    """Ensure error messages never leak Python tracebacks or local directory paths."""
    # Pass empty zip payload
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(analyze_project(file=UploadFile(filename="empty.zip", file=io.BytesIO(b""))))

    detail = str(exc_info.value.detail)
    assert "Traceback" not in detail
    assert "C:\\" not in detail
    assert "/home" not in detail


def test_no_code_execution_or_disk_extraction(tmp_path, monkeypatch):
    """Confirm analyze_project never executes code or writes files to disk."""
    monkeypatch.chdir(tmp_path)
    # Dangerous code that would raise if executed or imported
    malicious_code = b"""import sys
raise SystemExit('Malicious execution was triggered!')
"""
    archive_data = _create_zip({
        "danger.py": malicious_code,
        "README.md": b"# Test",
    })
    upload = UploadFile(filename="safe_check.zip", file=io.BytesIO(archive_data))

    # Should run smoothly without triggering SystemExit
    response = asyncio.run(analyze_project(file=upload))
    assert response.status_code == 200

    # Confirm disk remains 100% clean
    assert list(tmp_path.iterdir()) == []
