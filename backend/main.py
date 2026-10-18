"""TRASHAK AI - Backend Application Entry Point.

FastAPI application orchestrating project archive validation, structural analysis,
dependency diagnosis, intent reconstruction, and prioritized recovery planning.
"""

from typing import Any, Dict
from fastapi import FastAPI, File, HTTPException, UploadFile, status
from fastapi.responses import JSONResponse

from backend.ai.intent_reconstructor import reconstruct_intent
from backend.ai.recovery_planner import generate_recovery_plan
from backend.core.archive_validator import validate_archive
from backend.core.file_inventory import build_inventory
from backend.scanner.code_analyzer import analyze_python_code
from backend.scanner.dependency_analyzer import analyze_dependencies

# Configurable limit: 25 MiB maximum compressed upload size
MAX_UPLOAD_SIZE: int = 25 * 1024 * 1024
CHUNK_SIZE: int = 1024 * 1024  # 1 MiB stream chunks

app = FastAPI(
    title="TRASHAK AI API",
    description="Automated Recovery Platform for Abandoned and Incomplete Software Projects",
    version="0.1.0",
)


@app.get("/")
def read_root() -> Dict[str, Any]:
    """Service information and API catalog."""
    return {
        "project": "TRASHAK AI",
        "description": "AI-Powered Abandoned Software Project Recovery Platform",
        "status": "online",
        "version": "0.1.0",
        "endpoints": {
            "root": "/",
            "health": "/health",
            "docs": "/docs",
            "analyze": "/analyze",
        },
    }


@app.get("/health")
def health_check() -> Dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}


@app.post("/analyze")
async def analyze_project(
    file: UploadFile = File(..., description="ZIP archive of the software project to analyze"),
) -> JSONResponse:
    """Accept an uploaded software project ZIP, run the recovery pipeline, and return a consolidated report.

    Pipeline execution sequence:
    1. Secure ZIP validation
    2. Project file inventory scanning
    3. Python code structure analysis (AST)
    4. Dependency and health analysis
    5. Intent reconstruction
    6. Prioritized recovery plan generation

    Never extracts files to disk or executes uploaded content.
    """
    # 1. Validate file presence
    if not file or not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file uploaded or filename is missing.",
        )

    # 2. Validate ZIP extension/type
    filename_lower = file.filename.lower()
    if not filename_lower.endswith(".zip"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only ZIP archives (.zip) are supported.",
        )

    # 3. Read uploaded bytes with bounded stream limit
    try:
        buffer = bytearray()
        while True:
            chunk = await file.read(CHUNK_SIZE)
            if not chunk:
                break
            buffer.extend(chunk)
            if len(buffer) > MAX_UPLOAD_SIZE:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail=f"Uploaded file exceeds maximum allowed size ({len(buffer)} > {MAX_UPLOAD_SIZE} bytes).",
                )

        if len(buffer) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded archive is empty (0 bytes).",
            )

        data = bytes(buffer)

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to read uploaded file payload.",
        )

    # 4. Pipeline Execution
    try:
        # Step 1: Secure ZIP validation
        validation = validate_archive(data)
        if not validation["valid"]:
            # Format validation failure into a structured 400 response
            recovery_plan = generate_recovery_plan({"validation": validation})
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "status": "rejected",
                    "message": "Archive failed security or format validation.",
                    "validation": validation,
                    "inventory": None,
                    "code_analysis": None,
                    "dependencies": None,
                    "intent": None,
                    "recovery_plan": recovery_plan,
                },
            )

        # Step 2: File inventory scanning
        inventory = build_inventory(data)

        # Step 3: Python code structure analysis
        code_analysis = analyze_python_code(data)

        # Step 4: Dependency and health analysis
        dependencies = analyze_dependencies(data)

        # Step 5: Intent reconstruction
        intent = reconstruct_intent(data)

        # Step 6: Prioritized recovery plan generation
        combined_analysis = {
            "validation": validation,
            "inventory": inventory,
            "code_analysis": code_analysis,
            "dependencies": dependencies,
            "intent": intent,
        }
        recovery_plan = generate_recovery_plan(combined_analysis)

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "success",
                "validation": validation,
                "inventory": inventory,
                "code_analysis": code_analysis,
                "dependencies": dependencies,
                "intent": intent,
                "recovery_plan": recovery_plan,
            },
        )

    except Exception:
        # Handle unexpected internal errors gracefully without exposing tracebacks
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected internal error occurred while processing the project archive.",
        )
