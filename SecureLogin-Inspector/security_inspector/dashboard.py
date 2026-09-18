import streamlit as st
import requests
import os
import textwrap
from datetime import datetime

from security_checks import run_security_scan
from security_score import analyze_scan
from url_validator import validate_url
from report_generator import generate_security_report


# ============================================================
# SECURELOGIN INSPECTOR
# WEB SECURITY ANALYSIS DASHBOARD
# ============================================================


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="SecureLogin Inspector",
    page_icon="🔐",
    layout="wide"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    textwrap.dedent("""
    <style>
        .main-title {
            font-size: 42px;
            font-weight: 700;
            margin-bottom: 5px;
            color: #111827 !important;
        }

        .subtitle {
            font-size: 18px;
            color: #4b5563 !important;
            margin-bottom: 25px;
        }

        .score-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 18px;
            margin-bottom: 20px;
        }

        .score-card {
            padding: 22px;
            border-radius: 15px;
            background: #f5f5f5 !important;
            color: #111827 !important;
            text-align: center;
            border: 1px solid #e5e7eb;
            min-height: 125px;
            box-sizing: border-box;
        }

        .score-card * {
            color: #111827 !important;
        }

        .score-label {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 12px;
        }

        .score-number {
            font-size: 42px;
            font-weight: bold;
            line-height: 1.1;
        }

        .grade {
            font-size: 30px;
            font-weight: bold;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 18px;
            margin-bottom: 20px;
        }

        .summary-card {
            padding: 18px;
            border-radius: 12px;
            background: #ffffff !important;
            color: #111827 !important;
            border: 1px solid #e5e7eb;
            text-align: center;
            box-sizing: border-box;
        }

        .summary-card * {
            color: #111827 !important;
        }

        .summary-value {
            font-size: 32px;
            font-weight: 700;
            margin-top: 6px;
        }

        .status-pass {
            color: #008000 !important;
            font-weight: bold;
        }

        .status-warning {
            color: #d97706 !important;
            font-weight: bold;
        }

        .status-fail {
            color: #dc2626 !important;
            font-weight: bold;
        }

        .section-title {
            font-size: 24px;
            font-weight: 600;
            margin-top: 20px;
            margin-bottom: 10px;
            color: #111827 !important;
        }

        @media print {
            @page {
                size: A4;
                margin: 10mm;
            }

            html, body {
                background: #ffffff !important;
                color: #111827 !important;
            }

            .stApp,
            [data-testid="stAppViewContainer"],
            [data-testid="stAppViewBlockContainer"],
            .main,
            .block-container {
                background: #ffffff !important;
                color: #111827 !important;
            }

            [data-testid="stSidebar"],
            [data-testid="stHeader"],
            footer,
            .pdf-section {
                display: none !important;
            }

            .score-grid,
            .summary-grid,
            .score-card,
            .summary-card {
                break-inside: avoid;
            }

            .score-card,
            .summary-card {
                background: #f5f5f5 !important;
                color: #111827 !important;
            }

            .score-card *,
            .summary-card *,
            .section-title,
            .main-title,
            .subtitle {
                color: #111827 !important;
            }

            .stProgress > div > div {
                background: #ffffff !important;
            }

            * {
                -webkit-print-color-adjust: exact !important;
                print-color-adjust: exact !important;
            }
        }
    </style>
    """),
    unsafe_allow_html=True
)


# ============================================================
# SESSION STATE
# ============================================================

if "scan_result" not in st.session_state:
    st.session_state.scan_result = None

if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🔐 SecureLogin Inspector</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">Passive Web Security Configuration Analyzer</div>',
    unsafe_allow_html=True
)


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("⚙️ Scan Settings")

scan_mode = st.sidebar.radio(
    "Select Scan Mode",
    [
        "🌐 Web Audit Mode",
        "💻 Local Test Mode"
    ]
)


# ============================================================
# TARGET URL
# ============================================================

if scan_mode == "💻 Local Test Mode":

    target_url = st.sidebar.text_input(
        "Target URL",
        value="http://127.0.0.1:5000"
    )

else:

    target_url = st.sidebar.text_input(
        "Target URL",
        value="https://example.com"
    )


# ============================================================
# INFORMATION
# ============================================================

if scan_mode == "🌐 Web Audit Mode":

    st.sidebar.info(
        """
        Web Audit Mode performs passive checks
        against public HTTP/HTTPS targets.

        Only scan websites you own or have
        explicit permission to assess.
        """
    )

else:

    st.sidebar.info(
        """
        Local Test Mode is intended for applications
        running on your own computer.

        Example:

        http://127.0.0.1:5000
        """
    )


# ============================================================
# SCAN BUTTON
# ============================================================

scan_button = st.sidebar.button(
    "🔍 Start Security Scan",
    use_container_width=True
)


# ============================================================
# SCAN PROCESS
# ============================================================

if scan_button:

    target_url = target_url.strip()

    # --------------------------------------------------------
    # LOCAL MODE VALIDATION
    # --------------------------------------------------------

    if scan_mode == "💻 Local Test Mode":

        parsed_local = target_url.lower()

        if not (
            parsed_local.startswith(
                "http://127.0.0.1"
            )
            or
            parsed_local.startswith(
                "http://localhost"
            )
            or
            parsed_local.startswith(
                "http://127.0.0.1:"
            )
            or
            parsed_local.startswith(
                "http://localhost:"
            )
        ):

            st.error(
                "🚫 Local Test Mode only accepts "
                "localhost or 127.0.0.1."
            )

        else:

            with st.spinner(
                "Running local security analysis..."
            ):

                try:

                    scan = run_security_scan(
                        target_url
                    )

                    analysis = analyze_scan(
                        scan
                    )

                    st.session_state.scan_result = scan

                    st.session_state.analysis_result = analysis

                    st.success(
                        "✅ Local security scan completed."
                    )

                except requests.RequestException as error:

                    st.error(
                        "🌐 Unable to connect to the local application."
                    )

                    st.caption(
                        str(error)
                    )

                except Exception as error:

                    st.error(
                        f"❌ Scan failed: {error}"
                    )

    # --------------------------------------------------------
    # WEB AUDIT MODE
    # --------------------------------------------------------

    else:

        validation = validate_url(
            target_url
        )

        if not validation["valid"]:

            st.error(
                "🚫 Scan blocked: "
                + validation["message"]
            )

        else:

            with st.spinner(
                "Running passive security analysis..."
            ):

                try:

                    scan = run_security_scan(
                        target_url
                    )

                    analysis = analyze_scan(
                        scan
                    )

                    st.session_state.scan_result = scan

                    st.session_state.analysis_result = analysis

                    st.success(
                        "✅ Web security scan completed."
                    )

                except requests.RequestException as error:

                    st.error(
                        "🌐 Unable to connect to the website."
                    )

                    st.caption(
                        str(error)
                    )

                except Exception as error:

                    st.error(
                        f"❌ Scan failed: {error}"
                    )


# ============================================================
# GET STORED RESULTS
# ============================================================

scan = st.session_state.scan_result
analysis = st.session_state.analysis_result


# ============================================================
# DISPLAY RESULTS
# ============================================================

if scan is not None and analysis is not None:

    # ========================================================
    # TARGET INFORMATION
    # ========================================================

    st.markdown(
        '<div class="section-title">🎯 Target Information</div>',
        unsafe_allow_html=True
    )

    col1, col2 = st.columns(2)

    with col1:

        st.write("**Target URL**")

        st.code(
            scan.get(
                "target",
                "Unknown"
            )
        )

    with col2:

        st.write("**Scan Time**")

        st.write(
            datetime.now().strftime(
                "%d-%m-%Y %H:%M:%S"
            )
        )


    # ========================================================
    # SECURITY SCORE
    # ========================================================

    score = analysis.get(
        "score",
        scan.get(
            "score",
            0
        )
    )

    grade = analysis.get(
        "grade",
        "N/A"
    )

    severity = analysis.get(
        "severity",
        "NONE"
    )

    st.markdown(
        textwrap.dedent(f"""
        <div class="score-grid">
            <div class="score-card">
                <div class="score-label">Security Score</div>
                <div class="score-number">{score}/100</div>
            </div>
            <div class="score-card">
                <div class="score-label">Security Grade</div>
                <div class="grade">{grade}</div>
            </div>
            <div class="score-card">
                <div class="score-label">Overall Severity</div>
                <div class="grade">{severity}</div>
            </div>
        </div>
        """),
        unsafe_allow_html=True
    )

    # ========================================================
    # SCORE PROGRESS
    # ========================================================

    try:

        numeric_score = float(
            score
        )

        numeric_score = max(
            0,
            min(
                100,
                numeric_score
            )
        )

        st.progress(
            numeric_score / 100
        )

    except:

        pass


    # ========================================================
    # SUMMARY COUNTS
    # ========================================================

    passed = analysis.get(
        "passed",
        []
    )

    warnings = analysis.get(
        "warnings",
        []
    )

    failed = analysis.get(
        "failed",
        []
    )

    st.markdown(
        textwrap.dedent(f"""
        <div class="summary-grid">
            <div class="summary-card">
                <div>✅ Passed</div>
                <div class="summary-value">{len(passed)}</div>
            </div>
            <div class="summary-card">
                <div>⚠️ Warnings</div>
                <div class="summary-value">{len(warnings)}</div>
            </div>
            <div class="summary-card">
                <div>❌ Failed</div>
                <div class="summary-value">{len(failed)}</div>
            </div>
        </div>
        """),
        unsafe_allow_html=True
    )

    # ========================================================
    # SECURITY FINDINGS
    # ========================================================

    st.markdown(
        '<div class="section-title">🚨 Security Findings</div>',
        unsafe_allow_html=True
    )

    issues = analysis.get(
        "issues",
        []
    )

    if not issues:

        st.success(
            "✅ No major security configuration issues were detected."
        )

    else:

        for index, issue in enumerate(
            issues,
            start=1
        ):

            title = issue.get(
                "title",
                "Security Issue"
            )

            issue_severity = issue.get(
                "severity",
                "LOW"
            )

            description = issue.get(
                "description",
                ""
            )

            recommendation = issue.get(
                "recommendation",
                ""
            )

            with st.expander(
                f"{index}. {title} — {issue_severity}"
            ):

                st.write(
                    "**Description:**"
                )

                st.write(
                    description
                )

                st.write(
                    "**Recommendation:**"
                )

                st.write(
                    recommendation
                )


    # ========================================================
    # SECURITY CHECKS
    # ========================================================

    st.markdown(
        '<div class="section-title">🛡️ Security Checks</div>',
        unsafe_allow_html=True
    )

    checks = scan.get(
        "checks",
        []
    )

    if checks:

        for check in checks:

            check_name = check.get(
                "name",
                "Unknown Check"
            )

            status = check.get(
                "status",
                "INFO"
            )

            check_severity = check.get(
                "severity",
                "INFO"
            )

            message = check.get(
                "message",
                ""
            )

            check_score = check.get(
                "score",
                0
            )

            if status.upper() == "PASS":

                icon = "✅"

            elif status.upper() == "WARNING":

                icon = "⚠️"

            elif status.upper() == "FAIL":

                icon = "❌"

            else:

                icon = "ℹ️"

            with st.expander(
                f"{icon} {check_name}"
            ):

                col1, col2, col3 = st.columns(3)

                with col1:

                    st.write(
                        "**Status**"
                    )

                    st.write(
                        status
                    )

                with col2:

                    st.write(
                        "**Severity**"
                    )

                    st.write(
                        check_severity
                    )

                with col3:

                    st.write(
                        "**Score**"
                    )

                    st.write(
                        f"{check_score}/10"
                    )

                if message:

                    st.write(
                        "**Details:**"
                    )

                    st.write(
                        message
                    )


    # ========================================================
    # RECOMMENDATIONS
    # ========================================================

    st.markdown(
        '<div class="section-title">💡 Recommendations</div>',
        unsafe_allow_html=True
    )

    recommendations = analysis.get(
        "recommendations",
        []
    )

    if recommendations:

        for number, recommendation in enumerate(
            recommendations,
            start=1
        ):

            st.write(
                f"**{number}.** {recommendation}"
            )

    else:

        st.info(
            "No additional recommendations were generated."
        )


    # ========================================================
    # RAW DATA
    # ========================================================

    st.markdown(
        '<div class="section-title">🧾 Raw Scan Data</div>',
        unsafe_allow_html=True
    )

    with st.expander(
        "View Raw Scan Data"
    ):

        st.json(
            scan
        )


    # ========================================================
    # PDF REPORT
    # ========================================================

    st.markdown(
        '<div class="pdf-section"><div class="section-title">📄 Security Report</div>',
        unsafe_allow_html=True
    )

    report_directory = os.path.abspath(
        os.path.join(
            os.path.dirname(
                os.path.abspath(__file__)
            ),
            "..",
            "reports"
        )
    )

    os.makedirs(
        report_directory,
        exist_ok=True
    )

    report_filename = (
        "security_report_"
        + datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )
        + ".pdf"
    )

    report_path = os.path.join(
        report_directory,
        report_filename
    )

    if st.button(
        "📥 Generate PDF Security Report",
        use_container_width=True
    ):

        try:

            generated_report = generate_security_report(
                scan,
                analysis,
                report_path
            )

            with open(
                generated_report,
                "rb"
            ) as pdf_file:

                pdf_data = pdf_file.read()

            st.success(
                "✅ PDF security report generated successfully."
            )

            st.download_button(
                label="⬇️ Download Security Report",
                data=pdf_data,
                file_name=report_filename,
                mime="application/pdf",
                use_container_width=True
            )

        except Exception as error:

            st.error(
                f"❌ Could not generate PDF report: {error}"
            )


# ============================================================
# START SCREEN
# ============================================================

else:

    st.info(
        "👈 Enter a target URL and click "
        "'Start Security Scan' to begin."
    )

    st.markdown(
        "### 🔍 What SecureLogin Inspector Checks"
    )

    col1, col2 = st.columns(2)

    with col1:

        st.write(
            """
            🔒 **HTTPS Configuration**

            Checks whether the target uses secure HTTPS.
            """
        )

        st.write(
            """
            🛡️ **Security Headers**

            Checks important HTTP security headers.
            """
        )

        st.write(
            """
            🍪 **Cookie Security**

            Checks Secure, HttpOnly and SameSite attributes.
            """
        )

        st.write(
            """
            🔑 **Login Interface**

            Detects publicly visible password forms.
            """
        )

        st.write(
            """
            🔄 **HTTPS Redirect**

            Checks whether HTTP requests redirect to HTTPS.
            """
        )

    with col2:

        st.write(
            """
            🌐 **Mixed Content**

            Checks HTTPS pages for HTTP resources.
            """
        )

        st.write(
            """
            🖥️ **Server Disclosure**

            Checks for unnecessary server information.
            """
        )

        st.write(
            """
            📦 **Content Type**

            Checks HTTP content-type configuration.
            """
        )

        st.write(
            """
            🔄 **CORS Configuration**

            Checks publicly visible CORS settings.
            """
        )

        st.write(
            """
            📄 **PDF Security Report**

            Generates a downloadable security assessment.
            """
        )


# ============================================================
# FOOTER
# ============================================================

st.markdown("---")

st.caption(
    "SecureLogin Inspector • Passive Security Configuration Analysis • Educational Project"
)