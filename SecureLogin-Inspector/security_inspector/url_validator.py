import socket
import ipaddress
from urllib.parse import urlparse


# ============================================================
# SECURELOGIN INSPECTOR
# URL VALIDATOR
# ============================================================


def validate_url(url, allow_local=False):
    """
    Validate a URL before performing a passive security scan.

    allow_local=True:
        Allows localhost and private/local IP addresses.

    allow_local=False:
        Only public HTTP/HTTPS targets are accepted.
    """

    url = url.strip()

    # --------------------------------------------------------
    # Empty URL
    # --------------------------------------------------------

    if not url:
        return {
            "valid": False,
            "message": "URL cannot be empty."
        }

    # --------------------------------------------------------
    # Parse URL
    # --------------------------------------------------------

    parsed = urlparse(url)

    # --------------------------------------------------------
    # HTTP / HTTPS only
    # --------------------------------------------------------

    if parsed.scheme.lower() not in ("http", "https"):
        return {
            "valid": False,
            "message": "Only HTTP and HTTPS URLs are supported."
        }

    # --------------------------------------------------------
    # Hostname
    # --------------------------------------------------------

    hostname = parsed.hostname

    if not hostname:
        return {
            "valid": False,
            "message": "The URL does not contain a valid hostname."
        }

    hostname = hostname.lower()

    # --------------------------------------------------------
    # Reject username/password in URL
    # --------------------------------------------------------

    if parsed.username or parsed.password:
        return {
            "valid": False,
            "message": "URLs containing usernames or passwords are not accepted."
        }

    # --------------------------------------------------------
    # Port validation
    # --------------------------------------------------------

    try:
        port = parsed.port

    except ValueError:
        return {
            "valid": False,
            "message": "The URL contains an invalid port."
        }

    if port is not None:

        if allow_local:

            allowed_ports = {
                80,
                443,
                5000,
                8000,
                8080
            }

        else:

            allowed_ports = {
                80,
                443
            }

        if port not in allowed_ports:
            return {
                "valid": False,
                "message":
                    "This port is not allowed by the current scan mode."
            }

    # --------------------------------------------------------
    # Local mode
    # --------------------------------------------------------

    if allow_local:

        local_names = {
            "localhost",
            "localhost.localdomain"
        }

        if hostname in local_names:

            return {
                "valid": True,
                "message": "Localhost target accepted.",
                "hostname": hostname,
                "scheme": parsed.scheme.lower()
            }

    # --------------------------------------------------------
    # Resolve hostname
    # --------------------------------------------------------

    try:

        addresses = socket.getaddrinfo(
            hostname,
            None
        )

    except socket.gaierror:

        return {
            "valid": False,
            "message": "The hostname could not be resolved."
        }

    # --------------------------------------------------------
    # Check IP addresses
    # --------------------------------------------------------

    for address in addresses:

        ip = address[4][0]

        try:

            ip_obj = ipaddress.ip_address(ip)

        except ValueError:

            return {
                "valid": False,
                "message": "The resolved address is invalid."
            }

        # ----------------------------------------------------
        # Local mode
        # ----------------------------------------------------

        if allow_local:

            continue

        # ----------------------------------------------------
        # Public web mode
        # ----------------------------------------------------

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):

            return {
                "valid": False,
                "message":
                    "Private or non-public network addresses "
                    "are not allowed in Web Audit Mode."
            }

    # --------------------------------------------------------
    # Successful validation
    # --------------------------------------------------------

    return {
        "valid": True,
        "message": "URL passed validation.",
        "hostname": hostname,
        "scheme": parsed.scheme.lower()
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_urls = [

        "https://example.com",

        "http://example.com",

        "http://127.0.0.1:5000",

        "http://localhost:5000",

        "ftp://example.com"

    ]

    print()
    print("=" * 65)
    print(" SECURELOGIN INSPECTOR - URL VALIDATOR")
    print("=" * 65)

    for target in test_urls:

        result = validate_url(
            target,
            allow_local=False
        )

        print()
        print("URL:", target)

        if result["valid"]:
            print("Status: VALID")
        else:
            print("Status: BLOCKED")

        print("Message:", result["message"])

    print()
    print("=" * 65)