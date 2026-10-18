
import json
import os

import pandas as pd
import requests
import streamlit as st


# --------------------------------------------------
# Configuration
# --------------------------------------------------
API_BASE_URL = os.getenv(
    "TRASHAK_API_URL",
    "http://127.0.0.1:8000",
).rstrip("/")

MAX_UPLOAD_MB = 25


# --------------------------------------------------
# Page configuration and styling
# --------------------------------------------------
st.set_page_config(
    page_title="TRASHAK AI | Project Recovery",
    page_icon="🛠️",
    layout="wide",
    initial_sidebar_state="expanded",
)


st.markdown(
    """
    <style>
    /* App background and typography */
    .stApp {
        background:
            radial-gradient(ellipse at 80% 0%, #172744 0%, transparent 42%),
            linear-gradient(145deg, #080d19, #0c1424 65%, #101c30);
        color: #e6edf7;
    }

    [data-testid="stHeader"] {
        background: rgba(8, 13, 25, 0.85);
    }

    [data-testid="stMainBlockContainer"] {
        max-width: 1440px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    h1, h2, h3 {
        color: #f5f8ff !important;
        letter-spacing: -0.025em;
    }

    p, label, .stMarkdown, [data-testid="stCaptionContainer"] {
        color: #c0cde0;
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background: #090f1c;
        border-right: 1px solid #202d43;
    }

    [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] label {
        color: #b9c7dc !important;
    }

    /* Hero panel */
    .hero {
        padding: 2.2rem;
        border: 1px solid #304764;
        border-radius: 22px;
        background:
            linear-gradient(115deg,
                rgba(25, 43, 70, 0.98),
                rgba(17, 49, 67, 0.94));
        box-shadow: 0 18px 55px rgba(0, 0, 0, 0.18);
        margin-bottom: 1.8rem;
    }

    .hero h1 {
        font-size: 2.7rem;
        font-weight: 800;
        margin: 0 0 0.7rem 0;
        color: #ffffff !important;
    }

    .hero p {
        color: #c5d7ed !important;
        font-size: 1rem;
        line-height: 1.7;
        margin-bottom: 0.25rem;
    }

    .eyebrow {
        color: #6ee7f9 !important;
        text-transform: uppercase;
        letter-spacing: 0.14em;
        font-size: 0.75rem !important;
        font-weight: 700;
        margin-bottom: 0.6rem;
    }

    /* Upload area */
    [data-testid="stFileUploader"] {
        background: rgba(18, 29, 48, 0.85);
        border: 1px dashed #45617f;
        border-radius: 16px;
        padding: 0.8rem;
    }

    [data-testid="stFileUploaderDropzone"] {
        background: #111d30 !important;
        border: 1px dashed #496789 !important;
        border-radius: 12px !important;
    }

    [data-testid="stFileUploaderDropzone"] * {
        color: #dce8f8 !important;
    }

    [data-testid="stFileUploaderDropzone"] button {
        background: #203752 !important;
        border: 1px solid #45617f !important;
        border-radius: 9px !important;
    }

    /* Metric cards */
    [data-testid="stMetric"] {
        background: linear-gradient(145deg, #17243a, #111c2e);
        border: 1px solid #293b56;
        border-radius: 15px;
        padding: 1.1rem;
        min-height: 112px;
    }

    [data-testid="stMetricLabel"] {
        color: #aebfd6 !important;
    }

    [data-testid="stMetricValue"] {
        color: #f5f8ff !important;
        font-weight: 750;
    }

    /* Buttons */
    .stButton > button,
    .stDownloadButton > button {
        border-radius: 10px;
        min-height: 2.8rem;
        font-weight: 650;
        transition: all 0.2s ease;
    }

    .stButton > button[kind="primary"] {
        background: linear-gradient(90deg, #2563eb, #0891b2);
        border: none;
        color: white;
    }

    .stButton > button:hover,
    .stDownloadButton > button:hover {
        border-color: #67e8f9;
        transform: translateY(-1px);
    }

    /* Tabs and report panels */
    .stTabs [data-baseweb="tab-list"] {
        gap: 0.35rem;
        border-bottom: 1px solid #293b56;
    }

    .stTabs [data-baseweb="tab"] {
        color: #b9c7dc;
        border-radius: 8px 8px 0 0;
        padding: 0.7rem 1rem;
    }

    .stTabs [aria-selected="true"] {
        color: #67e8f9 !important;
    }

    [data-testid="stExpander"] {
        background: rgba(19, 31, 50, 0.7);
        border: 1px solid #2b3e58;
        border-radius: 12px;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid #293b56;
        border-radius: 12px;
        overflow: hidden;
    }

    /* Status and alerts */
    [data-testid="stAlert"] {
        border-radius: 12px;
    }

    hr {
        border-color: #263750;
    }

    </style>
    """,
    unsafe_allow_html=True,
)



# --------------------------------------------------
# Helpers
# --------------------------------------------------
def get_dict(value):
    """Return a dictionary when the supplied value is valid."""
    return value if isinstance(value, dict) else {}


def get_list(value):
    """Return a list when the supplied value is valid."""
    return value if isinstance(value, list) else []


def display_json_download(report):
    """Offer the complete analysis as a downloadable JSON file."""
    payload = json.dumps(report, indent=2, ensure_ascii=False)

    st.download_button(
        label="⬇️ Download complete JSON report",
        data=payload,
        file_name="trashak_recovery_report.json",
        mime="application/json",
        use_container_width=True,
    )


def show_findings(findings):
    findings = get_list(findings)

    if not findings:
        st.info("No findings were returned by this module.")
        return

    for index, finding in enumerate(findings, start=1):
        if not isinstance(finding, dict):
            continue

        title = (
            finding.get("title")
            or finding.get("description")
            or finding.get("message")
            or f"Finding {index}"
        )

        severity = finding.get(
            "severity",
            finding.get("priority", "unspecified"),
        )

        with st.expander(f"{severity.upper()} · {title}"):
            st.json(finding)


def render_report(report):
    validation = get_dict(report.get("validation"))
    inventory = get_dict(report.get("inventory"))
    inventory_summary = get_dict(inventory.get("summary"))
    code = get_dict(report.get("code_analysis"))
    code_summary = get_dict(code.get("summary"))
    dependencies = get_dict(report.get("dependencies"))
    dependency_summary = get_dict(dependencies.get("summary"))
    intent = get_dict(report.get("intent"))
    plan = get_dict(report.get("recovery_plan"))
    plan_summary = get_dict(plan.get("summary"))

    counts = get_dict(
        inventory_summary.get(
            "counts_by_category",
            inventory_summary.get("categories", {}),
        )
    )

    actions = get_list(plan.get("actions"))
    files = get_list(inventory.get("files"))
    evidence = get_list(intent.get("evidence"))

    st.success("Analysis completed.")

    st.subheader("Project overview")

    st.markdown(
        f"### {intent.get('project_name') or 'Project name undetermined'}"
    )
    st.write(
        intent.get("probable_purpose")
        or "The system could not determine the project's purpose reliably."
    )

    metrics = st.columns(4)
    metrics[0].metric(
        "Files discovered",
        inventory_summary.get("total_files", len(files)),
    )
    metrics[1].metric(
        "Python files",
        code_summary.get("total_python_files", 0),
    )
    metrics[2].metric(
        "Health findings",
        dependency_summary.get("health_findings_count", 0),
    )
    metrics[3].metric(
        "Recovery actions",
        plan_summary.get("total_recovery_actions", len(actions)),
    )

    st.caption(
        f"Overall status: {report.get('status', 'unknown')} · "
        f"Archive valid: {validation.get('valid', 'unknown')}"
    )

    st.divider()

    # --------------------------------------------------
    # Results tabs
    # --------------------------------------------------
    overview_tab, files_tab, code_tab, deps_tab, intent_tab, plan_tab = (
        st.tabs(
            [
                "📊 Overview",
                "📁 File Inventory",
                "🧩 Code Analysis",
                "📦 Dependencies",
                "🧠 Project Intent",
                "🛠️ Recovery Plan",
            ]
        )
    )

    with overview_tab:
        st.subheader("File categories")

        if counts:
            category_data = [
                {"Category": name, "Files": count}
                for name, count in counts.items()
            ]
            st.bar_chart(
                pd.DataFrame(category_data).set_index("Category")
            )
        else:
            st.info("No category counts are available.")

        st.subheader("Archive validation")
        st.json(validation)

        st.subheader("Analysis issues")
        issues = get_list(report.get("issues"))
        if issues:
            for issue in issues:
                st.warning(str(issue))
        else:
            st.success("No top-level analysis issues were reported.")

    with files_tab:
        st.subheader("Project file inventory")

        if files:
            st.dataframe(
                pd.DataFrame(files),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No file records are available.")

        st.write(
            "Ignored entries:",
            inventory.get("ignored_entries", 0),
        )

    with code_tab:
        st.subheader("Python structure")

        st.write(
            "Functions:",
            code_summary.get("function_count", 0),
            " · Classes:",
            code_summary.get("class_count", 0),
            " · Imports:",
            code_summary.get("import_count", 0),
        )

        entry_points = get_list(
            code_summary.get("entry_point_candidates")
        )
        st.write("Entry-point candidates:", entry_points or "None identified")

        for source_file in get_list(code.get("files")):
            if not isinstance(source_file, dict):
                continue

            with st.expander(source_file.get("path", "Unknown file")):
                st.write(
                    "Parsed:",
                    source_file.get("parsed", "unknown"),
                )
                st.write(
                    "Lines:",
                    source_file.get("line_count", 0),
                )
                st.write("Functions:", source_file.get("functions", []))
                st.write("Classes:", source_file.get("classes", []))
                st.write("Imports:", source_file.get("imports", []))

                if source_file.get("syntax_error"):
                    st.error(str(source_file["syntax_error"]))

        show_findings(code.get("findings"))

    with deps_tab:
        st.subheader("Dependency manifests")

        manifests = get_list(dependencies.get("manifests"))
        if manifests:
            st.dataframe(
                pd.DataFrame(manifests),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No dependency manifests were found.")

        st.subheader("Declared dependencies")

        declared = get_list(dependencies.get("dependencies"))
        if declared:
            st.dataframe(
                pd.DataFrame(declared),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No declared dependencies were returned.")

        show_findings(dependencies.get("findings"))

    with intent_tab:
        st.subheader("Reconstructed intent")

        st.write(
            "**Confidence:**",
            intent.get("confidence", "unknown"),
        )

        st.write("**Likely features**")
        st.write(get_list(intent.get("likely_features")) or "Undetermined")

        st.write("**Probable architecture**")
        st.json(get_dict(intent.get("probable_architecture")))

        st.write("**Likely entry points**")
        st.json(get_list(intent.get("likely_entry_points")))

        st.subheader("Supporting evidence")

        for item in evidence:
            if not isinstance(item, dict):
                continue

            source = item.get("source", "Unknown source")
            observation = item.get("observation", "No observation provided")

            with st.expander(f"{source} · {item.get('type', 'evidence')}"):
                st.write(observation)
                st.write(item.get("relevance", ""))

        st.subheader("Uncertainties and limitations")
        st.write(
            get_list(intent.get("incomplete_or_uncertain_areas"))
            or "No uncertain areas were reported."
        )
        st.write(get_list(intent.get("limitations")))

    with plan_tab:
        st.subheader("Prioritized recovery actions")

        by_priority = get_dict(
            plan_summary.get("actions_by_priority")
        )

        if by_priority:
            priority_columns = st.columns(4)
            for column, priority in zip(
                priority_columns,
                ["critical", "high", "medium", "low"],
            ):
                column.metric(
                    priority.title(),
                    by_priority.get(priority, 0),
                )

        st.write(
            "**Recommended first action:**",
            plan_summary.get("recommended_first_action")
            or "No first action was identified.",
        )

        st.write("**Blockers:**")
        st.write(get_list(plan_summary.get("blockers")) or "None reported.")

        for action in actions:
            if not isinstance(action, dict):
                continue

            action_id = action.get("id", "Action")
            title = action.get("title", "Untitled action")
            priority = action.get("priority", "unknown")

            with st.expander(
                f"{action_id} · {priority.upper()} · {title}"
            ):
                st.write(action.get("description", ""))
                st.write("**Why it matters**")
                st.write(action.get("rationale", ""))

                st.write("**Suggested steps**")
                for step in get_list(action.get("suggested_steps")):
                    st.write(f"- {step}")

                st.write("**Evidence references**")
                st.json(get_list(action.get("evidence_references")))

                st.write(
                    "Confidence:",
                    action.get("confidence", "unknown"),
                )
                st.write(
                    "Human review required:",
                    action.get("requires_human_review", True),
                )

    st.divider()
    display_json_download(report)


# --------------------------------------------------
# Main page
# --------------------------------------------------
with st.sidebar:
    st.title("🛠️ TRASHAK AI")
    st.caption("Trace the Forgotten. Revive the Lost.")
    st.divider()

    st.write("Backend endpoint")
    st.code(f"{API_BASE_URL}/analyze", language="text")
    st.caption(f"Maximum upload size: {MAX_UPLOAD_MB} MB")

    if st.button("Check backend health", use_container_width=True):
        try:
            response = requests.get(
                f"{API_BASE_URL}/health",
                timeout=5,
            )
            response.raise_for_status()
            st.success("Backend is reachable.")
            st.json(response.json())
        except requests.RequestException as exc:
            st.error(f"Backend connection failed: {exc}")


st.markdown(
    """
    <div class="hero">
        <div class="eyebrow">Software Recovery Intelligence</div>
        <h1>🛠️ TRASHAK AI</h1>
        <p>
            <strong>Trace the Forgotten. Revive the Lost.</strong>
        </p>
        <p>
            Reconstruct project intent, uncover structural problems,
            and turn abandoned repositories into actionable recovery plans.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.subheader("Analyze an abandoned project")

st.write(
    "Upload a ZIP archive containing source code, documentation, "
    "configuration, and tests."
)

uploaded_file = st.file_uploader(
    "Choose a project ZIP archive",
    type=["zip"],
    accept_multiple_files=False,
)

if uploaded_file:
    size_mb = uploaded_file.size / (1024 * 1024)

    st.caption(
        f"Selected: {uploaded_file.name} · {size_mb:.2f} MB"
    )

    if size_mb > MAX_UPLOAD_MB:
        st.error(
            f"File exceeds the dashboard limit of {MAX_UPLOAD_MB} MB."
        )
    else:
        if st.button(
            "🔍 Analyze Project",
            type="primary",
            use_container_width=True,
        ):
            try:
                with st.spinner(
                    "Analyzing files, code structure, dependencies, "
                    "project intent, and recovery actions..."
                ):
                    response = requests.post(
                        f"{API_BASE_URL}/analyze",
                        files={
                            "file": (
                                uploaded_file.name,
                                uploaded_file.getvalue(),
                                "application/zip",
                            )
                        },
                        timeout=(10, 180),
                    )

                if not response.ok:
                    try:
                        detail = response.json().get(
                            "detail",
                            response.text,
                        )
                    except ValueError:
                        detail = response.text

                    st.error(
                        f"Analysis failed (HTTP {response.status_code}): "
                        f"{detail}"
                    )

                else:
                    report = response.json()

                    if not isinstance(report, dict):
                        st.error(
                            "The backend returned an unexpected response."
                        )
                    else:
                        st.session_state["trashak_report"] = report

            except requests.Timeout:
                st.error(
                    "The analysis request timed out. "
                    "Check the backend terminal before retrying."
                )
            except requests.RequestException:
                st.error(
                    "Could not connect to the backend. "
                    "Confirm that FastAPI is running at "
                    f"{API_BASE_URL}."
                )
            except ValueError:
                st.error("The backend did not return valid JSON.")

if "trashak_report" in st.session_state:
    st.divider()
    render_report(st.session_state["trashak_report"])
