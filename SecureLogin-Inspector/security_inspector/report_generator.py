from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)


# ============================================================
# SECURELOGIN INSPECTOR
# PDF REPORT GENERATOR
# ============================================================


def generate_security_report(
    scan,
    analysis,
    output_path
):

    # --------------------------------------------------------
    # Document
    # --------------------------------------------------------

    document = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    # --------------------------------------------------------
    # Styles
    # --------------------------------------------------------

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=24,
        leading=28,
        alignment=TA_CENTER,
        spaceAfter=10
    )

    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=11,
        leading=15,
        alignment=TA_CENTER,
        spaceAfter=20
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=16,
        leading=20,
        spaceBefore=12,
        spaceAfter=8
    )

    normal_style = ParagraphStyle(
        "NormalText",
        parent=styles["Normal"],
        fontSize=9.5,
        leading=14
    )

    small_style = ParagraphStyle(
        "Small",
        parent=styles["Normal"],
        fontSize=8,
        leading=11
    )

    # --------------------------------------------------------
    # Story
    # --------------------------------------------------------

    story = []

    # ========================================================
    # TITLE
    # ========================================================

    story.append(
        Spacer(1, 15 * mm)
    )

    story.append(
        Paragraph(
            "SECURELOGIN INSPECTOR",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Passive Web Security Assessment Report",
            subtitle_style
        )
    )

    story.append(
        Spacer(1, 5 * mm)
    )

    # ========================================================
    # TARGET INFORMATION
    # ========================================================

    story.append(
        Paragraph(
            "1. Assessment Information",
            heading_style
        )
    )

    target = scan.get(
        "target",
        "Unknown"
    )

    score = analysis.get(
        "score",
        0
    )

    grade = analysis.get(
        "grade",
        "N/A"
    )

    severity = analysis.get(
        "severity",
        "NONE"
    )

    info_data = [

        [
            Paragraph(
                "<b>Target URL</b>",
                normal_style
            ),

            Paragraph(
                str(target),
                normal_style
            )
        ],

        [
            Paragraph(
                "<b>Security Score</b>",
                normal_style
            ),

            Paragraph(
                f"{score}/100",
                normal_style
            )
        ],

        [
            Paragraph(
                "<b>Grade</b>",
                normal_style
            ),

            Paragraph(
                str(grade),
                normal_style
            )
        ],

        [
            Paragraph(
                "<b>Overall Severity</b>",
                normal_style
            ),

            Paragraph(
                str(severity),
                normal_style
            )
        ]
    ]

    info_table = Table(
        info_data,
        colWidths=[
            55 * mm,
            115 * mm
        ]
    )

    info_table.setStyle(
        TableStyle(
            [
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),

                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.whitesmoke
                ),

                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7
                )
            ]
        )
    )

    story.append(
        info_table
    )

    story.append(
        Spacer(1, 8 * mm)
    )

    # ========================================================
    # SUMMARY
    # ========================================================

    story.append(
        Paragraph(
            "2. Security Summary",
            heading_style
        )
    )

    passed_count = len(
        analysis.get(
            "passed",
            []
        )
    )

    warning_count = len(
        analysis.get(
            "warnings",
            []
        )
    )

    failed_count = len(
        analysis.get(
            "failed",
            []
        )
    )

    summary_data = [

        [
            Paragraph(
                "<b>Passed</b>",
                normal_style
            ),

            Paragraph(
                "<b>Warnings</b>",
                normal_style
            ),

            Paragraph(
                "<b>Failed</b>",
                normal_style
            )
        ],

        [
            str(passed_count),
            str(warning_count),
            str(failed_count)
        ]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[
            55 * mm,
            55 * mm,
            55 * mm
        ]
    )

    summary_table.setStyle(
        TableStyle(
            [
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),

                (
                    "ALIGN",
                    (0, 0),
                    (-1, -1),
                    "CENTER"
                ),

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.whitesmoke
                ),

                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    10
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                )
            ]
        )
    )

    story.append(
        summary_table
    )

    # ========================================================
    # FINDINGS
    # ========================================================

    story.append(
        Paragraph(
            "3. Security Findings",
            heading_style
        )
    )

    issues = analysis.get(
        "issues",
        []
    )

    if not issues:

        story.append(
            Paragraph(
                "No major security configuration issues were detected.",
                normal_style
            )
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

            finding_data = [

                [
                    Paragraph(
                        f"<b>Finding {index}</b>",
                        normal_style
                    ),

                    Paragraph(
                        f"<b>{title}</b>",
                        normal_style
                    )
                ],

                [
                    Paragraph(
                        "<b>Severity</b>",
                        normal_style
                    ),

                    Paragraph(
                        issue_severity,
                        normal_style
                    )
                ],

                [
                    Paragraph(
                        "<b>Description</b>",
                        normal_style
                    ),

                    Paragraph(
                        description,
                        normal_style
                    )
                ],

                [
                    Paragraph(
                        "<b>Recommendation</b>",
                        normal_style
                    ),

                    Paragraph(
                        recommendation,
                        normal_style
                    )
                ]
            ]

            finding_table = Table(
                finding_data,
                colWidths=[
                    40 * mm,
                    130 * mm
                ]
            )

            finding_table.setStyle(
                TableStyle(
                    [
                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            0.5,
                            colors.grey
                        ),

                        (
                            "BACKGROUND",
                            (0, 0),
                            (0, -1),
                            colors.whitesmoke
                        ),

                        (
                            "VALIGN",
                            (0, 0),
                            (-1, -1),
                            "TOP"
                        ),

                        (
                            "LEFTPADDING",
                            (0, 0),
                            (-1, -1),
                            7
                        ),

                        (
                            "RIGHTPADDING",
                            (0, 0),
                            (-1, -1),
                            7
                        ),

                        (
                            "TOPPADDING",
                            (0, 0),
                            (-1, -1),
                            6
                        ),

                        (
                            "BOTTOMPADDING",
                            (0, 0),
                            (-1, -1),
                            6
                        )
                    ]
                )
            )

            story.append(
                finding_table
            )

            story.append(
                Spacer(1, 5 * mm)
            )

    # ========================================================
    # CHECK DETAILS
    # ========================================================

    story.append(
        PageBreak()
    )

    story.append(
        Paragraph(
            "4. Detailed Security Checks",
            heading_style
        )
    )

    check_rows = [

        [
            Paragraph(
                "<b>Security Check</b>",
                small_style
            ),

            Paragraph(
                "<b>Status</b>",
                small_style
            ),

            Paragraph(
                "<b>Severity</b>",
                small_style
            ),

            Paragraph(
                "<b>Score</b>",
                small_style
            )
        ]
    ]

    for check in scan.get(
        "checks",
        []
    ):

        check_name = check.get(
            "name",
            "Unknown"
        )

        status = check.get(
            "status",
            "INFO"
        )

        check_severity = check.get(
            "severity",
            "INFO"
        )

        check_score = check.get(
            "score",
            0
        )

        check_rows.append(
            [
                Paragraph(
                    check_name,
                    small_style
                ),

                Paragraph(
                    status,
                    small_style
                ),

                Paragraph(
                    check_severity,
                    small_style
                ),

                Paragraph(
                    f"{check_score}/10",
                    small_style
                )
            ]
        )

    check_table = Table(
        check_rows,
        colWidths=[
            75 * mm,
            30 * mm,
            35 * mm,
            30 * mm
        ],
        repeatRows=1
    )

    check_table.setStyle(
        TableStyle(
            [
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.whitesmoke
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),

                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                ),

                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                )
            ]
        )
    )

    story.append(
        check_table
    )

    # ========================================================
    # RECOMMENDATIONS
    # ========================================================

    story.append(
        Paragraph(
            "5. Recommendations",
            heading_style
        )
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

            story.append(
                Paragraph(
                    f"{number}. {recommendation}",
                    normal_style
                )
            )

            story.append(
                Spacer(
                    1,
                    2 * mm
                )
            )

    else:

        story.append(
            Paragraph(
                "No additional recommendations were generated.",
                normal_style
            )
        )

    # ========================================================
    # METHODOLOGY
    # ========================================================

    story.append(
        Paragraph(
            "6. Assessment Methodology",
            heading_style
        )
    )

    methodology = """
    SecureLogin Inspector performs passive HTTP-based security
    configuration analysis. The assessment examines publicly
    observable response headers, cookies, HTTPS configuration,
    login forms, page resources, server disclosure, content type,
    and CORS configuration. The tool does not perform brute-force
    attacks, password collection, authentication bypass, or
    exploitation.
    """

    story.append(
        Paragraph(
            methodology,
            normal_style
        )
    )

    # ========================================================
    # DISCLAIMER
    # ========================================================

    story.append(
        Paragraph(
            "7. Disclaimer",
            heading_style
        )
    )

    disclaimer = """
    This report is intended for educational and authorized
    security assessment purposes. A passive configuration scan
    cannot establish that a website is completely secure or
    insecure. Results should be reviewed by an authorized
    security professional or system owner.
    """

    story.append(
        Paragraph(
            disclaimer,
            normal_style
        )
    )

    # ========================================================
    # BUILD PDF
    # ========================================================

    document.build(
        story
    )

    return output_path