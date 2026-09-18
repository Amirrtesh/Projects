import requests

from urllib.parse import urljoin, urlparse

from html.parser import HTMLParser


# ============================================================
# SECURELOGIN INSPECTOR
# PASSIVE SECURITY SCANNER
# ============================================================


USER_AGENT = (
    "SecureLoginInspector/1.0 "
    "(Educational Passive Security Audit Tool)"
)

TIMEOUT = 8


# ============================================================
# HTML PARSER
# ============================================================


class PageParser(HTMLParser):

    def __init__(self):

        super().__init__()

        self.forms = []

        self.current_form = None

        self.password_inputs = 0

        self.scripts = []

        self.links = []

    # --------------------------------------------------------
    # Start tag
    # --------------------------------------------------------

    def handle_starttag(self, tag, attrs):

        attributes = dict(attrs)

        tag = tag.lower()

        # ----------------------------------------------------
        # FORM
        # ----------------------------------------------------

        if tag == "form":

            self.current_form = {
                "action": attributes.get("action", ""),
                "method": attributes.get(
                    "method",
                    "GET"
                ).upper(),

                "has_password": False
            }

            self.forms.append(
                self.current_form
            )

        # ----------------------------------------------------
        # INPUT
        # ----------------------------------------------------

        elif tag == "input":

            input_type = attributes.get(
                "type",
                "text"
            ).lower()

            if input_type == "password":

                self.password_inputs += 1

                if self.current_form is not None:

                    self.current_form[
                        "has_password"
                    ] = True

        # ----------------------------------------------------
        # SCRIPT
        # ----------------------------------------------------

        elif tag == "script":

            src = attributes.get(
                "src"
            )

            if src:

                self.scripts.append(src)

        # ----------------------------------------------------
        # LINK
        # ----------------------------------------------------

        elif tag == "link":

            href = attributes.get(
                "href"
            )

            if href:

                self.links.append(href)

    # --------------------------------------------------------
    # End tag
    # --------------------------------------------------------

    def handle_endtag(self, tag):

        if tag.lower() == "form":

            self.current_form = None


# ============================================================
# REQUEST SESSION
# ============================================================


def create_session():

    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml"
        }
    )

    return session


# ============================================================
# SERVER AVAILABILITY
# ============================================================


def check_server(url):

    session = create_session()

    try:

        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True
        )

        return {
            "name": "Server Availability",
            "status": "PASS",
            "severity": "INFO",
            "score": 10,
            "message":
                f"Server responded with HTTP {response.status_code}.",
            "details": {
                "status_code": response.status_code,
                "final_url": response.url
            }
        }

    except requests.RequestException as error:

        return {
            "name": "Server Availability",
            "status": "FAIL",
            "severity": "HIGH",
            "score": 0,
            "message": "Unable to connect to the target server.",
            "details": {
                "error": str(error)
            }
        }


# ============================================================
# HTTPS
# ============================================================


def check_https(url):

    parsed = urlparse(url)

    if parsed.scheme.lower() == "https":

        return {
            "name": "HTTPS Encryption",
            "status": "PASS",
            "severity": "INFO",
            "score": 10,
            "message":
                "The target uses HTTPS encryption."
        }

    return {
        "name": "HTTPS Encryption",
        "status": "FAIL",
        "severity": "HIGH",
        "score": 0,
        "message":
            "The target is using HTTP instead of HTTPS."
    }


# ============================================================
# HTTP -> HTTPS REDIRECT
# ============================================================


def check_https_redirect(url):

    parsed = urlparse(url)

    if parsed.scheme.lower() == "https":

        return {
            "name": "HTTP to HTTPS Redirect",
            "status": "PASS",
            "severity": "INFO",
            "score": 10,
            "message":
                "Target already uses HTTPS."
        }

    https_url = url.replace(
        "http://",
        "https://",
        1
    )

    session = create_session()

    try:

        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=False
        )

        location = response.headers.get(
            "Location",
            ""
        )

        if location.startswith("https://"):

            return {
                "name": "HTTP to HTTPS Redirect",
                "status": "PASS",
                "severity": "INFO",
                "score": 10,
                "message":
                    "HTTP requests redirect to HTTPS."
            }

        # ----------------------------------------------------
        # Try HTTPS directly
        # ----------------------------------------------------

        try:

            https_response = session.get(
                https_url,
                timeout=TIMEOUT,
                allow_redirects=True
            )

            if https_response.ok:

                return {
                    "name": "HTTP to HTTPS Redirect",
                    "status": "WARNING",
                    "severity": "MEDIUM",
                    "score": 5,
                    "message":
                        "HTTPS is available, but HTTP does not "
                        "redirect to HTTPS."
                }

        except requests.RequestException:
            pass

        return {
            "name": "HTTP to HTTPS Redirect",
            "status": "WARNING",
            "severity": "MEDIUM",
            "score": 5,
            "message":
                "HTTP does not appear to redirect to HTTPS."
        }

    except requests.RequestException as error:

        return {
            "name": "HTTP to HTTPS Redirect",
            "status": "WARNING",
            "severity": "MEDIUM",
            "score": 5,
            "message":
                "Unable to verify HTTPS redirection.",
            "details": {
                "error": str(error)
            }
        }


# ============================================================
# SECURITY HEADERS
# ============================================================


def check_security_headers(url):

    session = create_session()

    recommended_headers = {

        "X-Content-Type-Options":
            "Helps prevent MIME-type sniffing.",

        "X-Frame-Options":
            "Helps protect against clickjacking.",

        "Content-Security-Policy":
            "Helps reduce XSS and content injection risks.",

        "Referrer-Policy":
            "Controls referrer information.",

        "Permissions-Policy":
            "Controls access to browser features.",

        "Strict-Transport-Security":
            "Enforces HTTPS connections."
    }

    try:

        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True
        )

        headers = response.headers

        present = []

        missing = []

        for header, description in recommended_headers.items():

            if header in headers:

                present.append(header)

            else:

                missing.append(header)

        # ----------------------------------------------------
        # HSTS is mainly relevant for HTTPS
        # ----------------------------------------------------

        parsed = urlparse(response.url)

        if parsed.scheme.lower() != "https":

            if "Strict-Transport-Security" in present:

                present.remove(
                    "Strict-Transport-Security"
                )

            if (
                "Strict-Transport-Security"
                not in missing
            ):

                missing.append(
                    "Strict-Transport-Security"
                )

        if len(missing) == 0:

            status = "PASS"
            score = 10
            severity = "INFO"

            message = (
                "Recommended security headers "
                "were detected."
            )

        elif len(present) >= 3:

            status = "WARNING"
            score = 6
            severity = "MEDIUM"

            message = (
                f"{len(present)} recommended headers "
                "were detected, but some are missing."
            )

        else:

            status = "FAIL"
            score = 2
            severity = "HIGH"

            message = (
                "Several recommended security headers "
                "are missing."
            )

        return {
            "name": "Security Headers",
            "status": status,
            "severity": severity,
            "score": score,
            "message": message,
            "details": {
                "present": present,
                "missing": missing
            }
        }

    except requests.RequestException as error:

        return {
            "name": "Security Headers",
            "status": "FAIL",
            "severity": "HIGH",
            "score": 0,
            "message":
                "Unable to inspect security headers.",
            "details": {
                "error": str(error)
            }
        }


# ============================================================
# COOKIES
# ============================================================


def check_cookies(url):

    session = create_session()

    try:

        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True
        )

        cookies = response.cookies

        if not cookies:

            return {
                "name": "Cookie Security",
                "status": "PASS",
                "severity": "INFO",
                "score": 10,
                "message":
                    "No cookies were set by the scanned response.",
                "details": {
                    "cookies": []
                }
            }

        insecure = []

        cookie_details = []

        for cookie in cookies:

            secure = bool(
                cookie.secure
            )

            httponly = bool(
                cookie.has_nonstandard_attr(
                    "HttpOnly"
                )
                or cookie._rest.get(
                    "HttpOnly"
                ) is not None
            )

            samesite = cookie._rest.get(
                "SameSite"
            )

            cookie_info = {
                "name": cookie.name,
                "secure": secure,
                "httponly": httponly,
                "samesite": samesite
            }

            cookie_details.append(
                cookie_info
            )

            problems = []

            if not secure:
                problems.append(
                    "Secure missing"
                )

            if not httponly:
                problems.append(
                    "HttpOnly missing"
                )

            if not samesite:
                problems.append(
                    "SameSite missing"
                )

            if problems:

                insecure.append(
                    {
                        "name": cookie.name,
                        "problems": problems
                    }
                )

        if not insecure:

            return {
                "name": "Cookie Security",
                "status": "PASS",
                "severity": "INFO",
                "score": 10,
                "message":
                    "Cookies use recommended security attributes.",
                "details": {
                    "cookies": cookie_details
                }
            }

        if len(insecure) < len(cookies):

            return {
                "name": "Cookie Security",
                "status": "WARNING",
                "severity": "MEDIUM",
                "score": 6,
                "message":
                    "Some cookies are missing recommended attributes.",
                "details": {
                    "cookies": cookie_details,
                    "issues": insecure
                }
            }

        return {
            "name": "Cookie Security",
            "status": "FAIL",
            "severity": "HIGH",
            "score": 2,
            "message":
                "Cookies are missing important security attributes.",
            "details": {
                "cookies": cookie_details,
                "issues": insecure
            }
        }

    except requests.RequestException as error:

        return {
            "name": "Cookie Security",
            "status": "WARNING",
            "severity": "MEDIUM",
            "score": 5,
            "message":
                "Unable to inspect cookies.",
            "details": {
                "error": str(error)
            }
        }


# ============================================================
# LOGIN ENDPOINT
# ============================================================


def check_login_endpoint(url):

    session = create_session()

    try:

        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True
        )

        parser = PageParser()

        parser.feed(
            response.text
        )

        if parser.password_inputs > 0:

            return {
                "name": "Login Interface Detection",
                "status": "PASS",
                "severity": "INFO",
                "score": 10,
                "message":
                    "A password input was detected.",
                "details": {
                    "password_inputs":
                        parser.password_inputs,
                    "forms":
                        len(parser.forms)
                }
            }

        return {
            "name": "Login Interface Detection",
            "status": "INFO",
            "severity": "INFO",
            "score": 8,
            "message":
                "No password input was detected on the scanned page.",
            "details": {
                "forms":
                    len(parser.forms)
            }
        }

    except requests.RequestException as error:

        return {
            "name": "Login Interface Detection",
            "status": "WARNING",
            "severity": "MEDIUM",
            "score": 5,
            "message":
                "Unable to inspect the page.",
            "details": {
                "error": str(error)
            }
        }


# ============================================================
# LOGIN FORM TRANSPORT
# ============================================================


def check_login_form_transport(url):

    session = create_session()

    try:

        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True
        )

        parser = PageParser()

        parser.feed(
            response.text
        )

        password_forms = [
            form
            for form in parser.forms
            if form["has_password"]
        ]

        if not password_forms:

            return {
                "name": "Login Form HTTPS Transport",
                "status": "INFO",
                "severity": "INFO",
                "score": 8,
                "message":
                    "No password form was detected on the page."
            }

        insecure_forms = []

        for form in password_forms:

            action = form["action"]

            if action:

                action_url = urljoin(
                    response.url,
                    action
                )

            else:

                action_url = response.url

            action_scheme = urlparse(
                action_url
            ).scheme.lower()

            if action_scheme != "https":

                insecure_forms.append(
                    action_url
                )

        if not insecure_forms:

            return {
                "name": "Login Form HTTPS Transport",
                "status": "PASS",
                "severity": "INFO",
                "score": 10,
                "message":
                    "Password forms submit over HTTPS.",
                "details": {
                    "password_forms":
                        len(password_forms)
                }
            }

        return {
            "name": "Login Form HTTPS Transport",
            "status": "FAIL",
            "severity": "HIGH",
            "score": 0,
            "message":
                "A password form may submit data over HTTP.",
            "details": {
                "insecure_actions":
                    insecure_forms
            }
        }

    except requests.RequestException as error:

        return {
            "name": "Login Form HTTPS Transport",
            "status": "WARNING",
            "severity": "MEDIUM",
            "score": 5,
            "message":
                "Unable to inspect login form transport.",
            "details": {
                "error": str(error)
            }
        }


# ============================================================
# MIXED CONTENT
# ============================================================


def check_mixed_content(url):

    session = create_session()

    try:

        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True
        )

        final_url = response.url

        parsed = urlparse(
            final_url
        )

        if parsed.scheme.lower() != "https":

            return {
                "name": "Mixed Content",
                "status": "INFO",
                "severity": "INFO",
                "score": 8,
                "message":
                    "Mixed-content analysis is only relevant to HTTPS pages."
            }

        parser = PageParser()

        parser.feed(
            response.text
        )

        insecure_resources = []

        resources = (
            parser.scripts
            + parser.links
        )

        for resource in resources:

            absolute_url = urljoin(
                final_url,
                resource
            )

            if absolute_url.startswith(
                "http://"
            ):

                insecure_resources.append(
                    absolute_url
                )

        if not insecure_resources:

            return {
                "name": "Mixed Content",
                "status": "PASS",
                "severity": "INFO",
                "score": 10,
                "message":
                    "No obvious HTTP mixed-content resources were detected."
            }

        return {
            "name": "Mixed Content",
            "status": "WARNING",
            "severity": "MEDIUM",
            "score": 5,
            "message":
                "HTTP resources were detected on an HTTPS page.",
            "details": {
                "resources":
                    insecure_resources[:20]
            }
        }

    except requests.RequestException as error:

        return {
            "name": "Mixed Content",
            "status": "WARNING",
            "severity": "MEDIUM",
            "score": 5,
            "message":
                "Unable to inspect page resources.",
            "details": {
                "error": str(error)
            }
        }


# ============================================================
# SERVER INFORMATION DISCLOSURE
# ============================================================


def check_server_disclosure(url):

    session = create_session()

    try:

        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True
        )

        server = response.headers.get(
            "Server"
        )

        powered_by = response.headers.get(
            "X-Powered-By"
        )

        disclosures = {}

        if server:

            disclosures["Server"] = server

        if powered_by:

            disclosures["X-Powered-By"] = powered_by

        if not disclosures:

            return {
                "name": "Server Information Disclosure",
                "status": "PASS",
                "severity": "INFO",
                "score": 10,
                "message":
                    "No obvious server technology disclosure was detected."
            }

        return {
            "name": "Server Information Disclosure",
            "status": "WARNING",
            "severity": "LOW",
            "score": 7,
            "message":
                "Server technology information is exposed.",
            "details": {
                "headers":
                    disclosures
            }
        }

    except requests.RequestException as error:

        return {
            "name": "Server Information Disclosure",
            "status": "WARNING",
            "severity": "LOW",
            "score": 5,
            "message":
                "Unable to inspect server headers.",
            "details": {
                "error": str(error)
            }
        }


# ============================================================
# CONTENT TYPE
# ============================================================


def check_content_type(url):

    session = create_session()

    try:

        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True
        )

        content_type = response.headers.get(
            "Content-Type",
            ""
        )

        if not content_type:

            return {
                "name": "Content-Type",
                "status": "WARNING",
                "severity": "LOW",
                "score": 5,
                "message":
                    "The response does not specify Content-Type."
            }

        return {
            "name": "Content-Type",
            "status": "PASS",
            "severity": "INFO",
            "score": 10,
            "message":
                f"Content-Type is {content_type}.",
            "details": {
                "content_type":
                    content_type
            }
        }

    except requests.RequestException as error:

        return {
            "name": "Content-Type",
            "status": "WARNING",
            "severity": "LOW",
            "score": 5,
            "message":
                "Unable to inspect Content-Type.",
            "details": {
                "error": str(error)
            }
        }


# ============================================================
# CORS
# ============================================================


def check_cors(url):

    session = create_session()

    try:

        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True
        )

        cors = response.headers.get(
            "Access-Control-Allow-Origin"
        )

        if not cors:

            return {
                "name": "CORS Configuration",
                "status": "PASS",
                "severity": "INFO",
                "score": 10,
                "message":
                    "No permissive CORS header was detected."
            }

        if cors.strip() == "*":

            return {
                "name": "CORS Configuration",
                "status": "WARNING",
                "severity": "MEDIUM",
                "score": 5,
                "message":
                    "CORS allows requests from any origin.",
                "details": {
                    "allow_origin":
                        cors
                }
            }

        return {
            "name": "CORS Configuration",
            "status": "PASS",
            "severity": "INFO",
            "score": 10,
            "message":
                "CORS uses a specific origin.",
            "details": {
                "allow_origin":
                    cors
            }
        }

    except requests.RequestException as error:

        return {
            "name": "CORS Configuration",
            "status": "WARNING",
            "severity": "MEDIUM",
            "score": 5,
            "message":
                "Unable to inspect CORS headers.",
            "details": {
                "error": str(error)
            }
        }


# ============================================================
# MAIN SCANNER
# ============================================================


def run_security_scan(url):

    results = []

    checks = [

        check_server,

        check_https,

        check_https_redirect,

        check_security_headers,

        check_cookies,

        check_login_endpoint,

        check_login_form_transport,

        check_mixed_content,

        check_server_disclosure,

        check_content_type,

        check_cors
    ]

    for check in checks:

        result = check(url)

        results.append(
            result
        )

    # --------------------------------------------------------
    # Calculate score
    # --------------------------------------------------------

    total_score = sum(
        result.get(
            "score",
            0
        )
        for result in results
    )

    max_score = len(results) * 10

    if max_score > 0:

        normalized_score = round(
            (
                total_score
                / max_score
            ) * 100,
            2
        )

    else:

        normalized_score = 0

    return {

        "target": url,

        "score": normalized_score,

        "checks": results
    }


# ============================================================
# TERMINAL TEST
# ============================================================


if __name__ == "__main__":

    target = "http://127.0.0.1:5000"

    print()
    print("=" * 65)
    print(" SECURELOGIN INSPECTOR")
    print(" PASSIVE SECURITY SCANNER")
    print("=" * 65)

    scan = run_security_scan(
        target
    )

    print()
    print("Target:", scan["target"])
    print("Score:", scan["score"])

    print()

    for result in scan["checks"]:

        print(
            f"{result['status']:8} "
            f"{result['name']}"
        )

        print(
            "         ",
            result["message"]
        )

    print()
    print("=" * 65)