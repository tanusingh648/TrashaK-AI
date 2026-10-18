# TRASHAK AI 🛠️

**TRASHAK AI** is an AI-powered abandoned software project recovery platform. It inspects abandoned, incomplete, or undocumented software repositories, reconstructs their intended purpose from source code and artifacts, pinpoints missing or broken components, and generates an actionable, explainable recovery plan.

---

## 🎯 Project Vision

Many repositories are abandoned with unfinished features, missing dependencies, deprecated syntax, or absent documentation. TRASHAK AI breathes life back into them by:
1. **Scanning Repositories**: Parsing code structure, configuration manifests, commits, and environment requirements.
2. **Reconstructing Intent**: Using semantic code analysis and retrieval to understand what the project was designed to do.
3. **Detecting Gaps**: Identifying missing files, broken imports, incomplete functions, and architectural holes.
4. **Generating Recovery Plans**: Providing step-by-step, explainable recovery roadmaps with remediation code.

---

## 🏗️ Architecture & Directory Layout

```text
Trashak AI/
├── backend/
│   ├── __init__.py
│   ├── main.py              # FastAPI application entry point
│   ├── core/                # Core configuration, models, and shared utilities
│   ├── scanner/             # Codebase parsing, AST extraction, manifest inspection
│   ├── ai/                  # AI orchestration, LLM prompts, model clients
│   ├── rag/                 # Semantic indexing, vector search, codebase retrieval
│   └── agents/              # Autonomous diagnostic & recovery agents
├── frontend/
│   └── app.py               # Streamlit interactive user interface
├── storage/                 # Local directory for uploaded/staged repositories
├── reports/                 # Generated diagnostic summaries and recovery plans
├── tests/                   # Automated unit and integration test suite
├── .gitignore               # Version control exclusion rules
├── requirements.txt         # Initial essential dependencies
└── README.md                # Project documentation
```

---

## 🚀 Getting Started

### Prerequisites
- **Python**: 3.10 compatible

### Virtual Environment Setup

A project-local virtual environment (`.venv`) is used to ensure isolated dependencies.

#### Windows (PowerShell)
```powershell
# Activate the existing virtual environment
.\.venv\Scripts\Activate.ps1

# Install foundational dependencies (upon approval)
pip install -r requirements.txt
```

#### Running the Backend
```powershell
uvicorn backend.main:app --reload
```
Once started, the backend API documentation will be available at:
- Swagger UI: `http://127.0.0.1:8000/docs`
- Health check: `http://127.0.0.1:8000/health`

#### Running the Frontend
```powershell
streamlit run frontend/app.py
```

---

## 🧪 Testing

To run the test suite:
```powershell
pytest
```

---

## 📌 Foundation Status

- [x] Initial project structure established
- [x] Python 3.10 `.venv` environment identified and configured
- [x] Baseline dependencies defined (`fastapi`, `uvicorn`, `streamlit`, `pytest`)
- [x] Exclusion rules configured in `.gitignore`
- [ ] Dependency installation (pending user approval)
- [ ] Core scanning and recovery features implementation
