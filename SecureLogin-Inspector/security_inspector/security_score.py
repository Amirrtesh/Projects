# ============================================================
# SECURELOGIN INSPECTOR
# SECURITY SCORE ANALYZER
# ============================================================


def analyze_scan(scan):

    checks = scan.get(
        "checks",
        []
    )

    score = scan.get(
        "score",
        0
    )

    passed = []

    warnings = []

    failed = []

    issues = []

    recommendations = []

    # ========================================================
    # PROCESS CHECKS
    # ========================================================

    for check in checks:

        name = check.get(
            "name",
            "Unknown Check"
        )

        status = check.get(
            "status",
            "INFO"
        )

        severity = check.get(
            "severity",
            "INFO"
        )

        message = check.get(
            "message",
            ""
        )

        # ----------------------------------------------------
        # PASS
        # ----------------------------------------------------

        if status == "PASS":

            passed.append(
                name
            )

        # ----------------------------------------------------
        # WARNING
        # ----------------------------------------------------

        elif status == "WARNING":

            warnings.append(
                name
            )

        # ----------------------------------------------------
        # FAIL
        # ----------------------------------------------------

        elif status == "FAIL":

            failed.append(
                name
            )

        # ====================================================
        # HTTPS
        # ====================================================

        if name == "HTTPS Encryption":

            if status == "FAIL":

                issues.append(
                    {
                        "title":
                            "HTTPS is not enabled",

                        "severity":
                            "HIGH",

                        "description":
                            message,

                        "recommendation":
                            "Enable HTTPS using a valid TLS certificate."
                    }
                )

                recommendations.append(
                    "Enable HTTPS for all sensitive communication."
                )

        # ====================================================
        # HTTPS REDIRECT
        # ====================================================

        elif name == "HTTP to HTTPS Redirect":

            if status == "WARNING":

                issues.append(
                    {
                        "title":
                            "HTTP does not redirect to HTTPS",

                        "severity":
                            "MEDIUM",

                        "description":
                            message,

                        "recommendation":
                            "Redirect all HTTP traffic to HTTPS."
                    }
                )

                recommendations.append(
                    "Configure HTTP-to-HTTPS redirection."
                )

        # ====================================================
        # SECURITY HEADERS
        # ====================================================

        elif name == "Security Headers":

            if status == "FAIL":

                issues.append(
                    {
                        "title":
                            "Security headers are missing",

                        "severity":
                            "HIGH",

                        "description":
                            message,

                        "recommendation":
                            "Configure recommended browser security headers."
                    }
                )

                recommendations.append(
                    "Add Content-Security-Policy, X-Content-Type-Options, "
                    "X-Frame-Options, Referrer-Policy and Permissions-Policy."
                )

            elif status == "WARNING":

                issues.append(
                    {
                        "title":
                            "Some security headers are missing",

                        "severity":
                            "MEDIUM",

                        "description":
                            message,

                        "recommendation":
                            "Review and configure missing security headers."
                    }
                )

                recommendations.append(
                    "Review missing HTTP security headers."
                )

        # ====================================================
        # COOKIE
        # ====================================================

        elif name == "Cookie Security":

            if status == "FAIL":

                issues.append(
                    {
                        "title":
                            "Cookie security attributes are missing",

                        "severity":
                            "HIGH",

                        "description":
                            message,

                        "recommendation":
                            "Use Secure, HttpOnly and SameSite attributes."
                    }
                )

                recommendations.append(
                    "Protect cookies with Secure, HttpOnly and SameSite."
                )

            elif status == "WARNING":

                issues.append(
                    {
                        "title":
                            "Some cookies need security attributes",

                        "severity":
                            "MEDIUM",

                        "description":
                            message,

                        "recommendation":
                            "Review cookie security configuration."
                    }
                )

                recommendations.append(
                    "Review cookie flags such as Secure, HttpOnly and SameSite."
                )

        # ====================================================
        # LOGIN FORM
        # ====================================================

        elif name == "Login Form HTTPS Transport":

            if status == "FAIL":

                issues.append(
                    {
                        "title":
                            "Login form may use insecure transport",

                        "severity":
                            "HIGH",

                        "description":
                            message,

                        "recommendation":
                            "Ensure login forms submit only over HTTPS."
                    }
                )

                recommendations.append(
                    "Submit authentication forms only through HTTPS."
                )

            elif status == "PASS":

                recommendations.append(
                    "Continue enforcing HTTPS for authentication endpoints."
                )

        # ====================================================
        # MIXED CONTENT
        # ====================================================

        elif name == "Mixed Content":

            if status == "WARNING":

                issues.append(
                    {
                        "title":
                            "Mixed content detected",

                        "severity":
                            "MEDIUM",

                        "description":
                            message,

                        "recommendation":
                            "Load page resources using HTTPS."
                    }
                )

                recommendations.append(
                    "Replace HTTP resources with HTTPS resources."
                )

        # ====================================================
        # SERVER DISCLOSURE
        # ====================================================

        elif name == "Server Information Disclosure":

            if status == "WARNING":

                issues.append(
                    {
                        "title":
                            "Server information is exposed",

                        "severity":
                            "LOW",

                        "description":
                            message,

                        "recommendation":
                            "Minimize unnecessary server technology disclosure."
                    }
                )

                recommendations.append(
                    "Review Server and X-Powered-By response headers."
                )

        # ====================================================
        # CORS
        # ====================================================

        elif name == "CORS Configuration":

            if status == "WARNING":

                issues.append(
                    {
                        "title":
                            "Permissive CORS configuration",

                        "severity":
                            "MEDIUM",

                        "description":
                            message,

                        "recommendation":
                            "Restrict allowed origins where appropriate."
                    }
                )

                recommendations.append(
                    "Avoid wildcard CORS when unrestricted access is unnecessary."
                )

        # ====================================================
        # CONTENT TYPE
        # ====================================================

        elif name == "Content-Type":

            if status == "WARNING":

                recommendations.append(
                    "Specify an appropriate Content-Type for server responses."
                )

    # ========================================================
    # REMOVE DUPLICATE RECOMMENDATIONS
    # ========================================================

    recommendations = list(
        dict.fromkeys(
            recommendations
        )
    )

    # ========================================================
    # DETERMINE SEVERITY
    # ========================================================

    issue_severities = [
        issue["severity"]
        for issue in issues
    ]

    if "HIGH" in issue_severities:

        overall_severity = "HIGH"

    elif "MEDIUM" in issue_severities:

        overall_severity = "MEDIUM"

    elif "LOW" in issue_severities:

        overall_severity = "LOW"

    else:

        overall_severity = "NONE"

    # ========================================================
    # DETERMINE GRADE
    # ========================================================

    if score >= 90:

        grade = "A+"

    elif score >= 80:

        grade = "A"

    elif score >= 70:

        grade = "B"

    elif score >= 60:

        grade = "C"

    elif score >= 50:

        grade = "D"

    else:

        grade = "F"

    # ========================================================
    # RETURN ANALYSIS
    # ========================================================

    return {

        "score": score,

        "grade": grade,

        "severity": overall_severity,

        "passed": passed,

        "warnings": warnings,

        "failed": failed,

        "issues": issues,

        "recommendations":
            recommendations
    }


# ============================================================
# TEST
# ============================================================


if __name__ == "__main__":

    test_scan = {

        "target":
            "https://example.com",

        "score":
            85,

        "checks": [

            {
                "name":
                    "HTTPS Encryption",

                "status":
                    "PASS",

                "severity":
                    "INFO",

                "message":
                    "HTTPS enabled."
            },

            {
                "name":
                    "Security Headers",

                "status":
                    "WARNING",

                "severity":
                    "MEDIUM",

                "message":
                    "Some headers are missing."
            }
        ]
    }

    result = analyze_scan(
        test_scan
    )

    print()
    print("=" * 60)
    print(" SECURITY ANALYSIS")
    print("=" * 60)

    print(
        "Score:",
        result["score"]
    )

    print(
        "Grade:",
        result["grade"]
    )

    print(
        "Severity:",
        result["severity"]
    )

    print(
        "Passed:",
        len(result["passed"])
    )

    print(
        "Warnings:",
        len(result["warnings"])
    )

    print(
        "Failed:",
        len(result["failed"])
    )

    print()