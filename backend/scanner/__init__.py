"""TRASHAK AI - Repository scanner and code inspection module."""

from backend.scanner.code_analyzer import analyze_python_code
from backend.scanner.dependency_analyzer import analyze_dependencies

__all__ = ["analyze_python_code", "analyze_dependencies"]
