import ipaddress
import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = ["login", "verify", "secure", "update", "banking", "account", "free", "bonus"]


def _is_ip_host(host: str) -> bool:
    """True for real IPs (IPv4 and IPv6) and for the obfuscated numeric forms
    browsers also accept, e.g. 2130706433, 0x7f000001, 0177.0.0.1."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    parts = host.split(".")
    return len(parts) <= 4 and all(
        re.fullmatch(r"0x[0-9a-f]+|\d+", part) for part in parts
    )


def analyze_url(url: str) -> dict:
    score_deduction = 0
    flags = []

    try:
        parsed = urlparse(url)
        # parsed.hostname (not netloc): netloc includes "user:pass@" and ":port",
        # which broke the IP check and handed check_tls() values like
        # "example.com:8443" or "google.com@evil.com" as the "domain".
        hostname = (parsed.hostname or "").rstrip(".")
    except ValueError:
        # urlparse raises on malformed input such as "http://[abc".
        # An empty domain tells the caller the URL is invalid.
        return {"domain": "", "deduction": 0, "flags": []}

    if not hostname:
        return {"domain": "", "deduction": 0, "flags": []}

    if parsed.scheme != "https":
        score_deduction += 25
        flags.append("Insecure protocol (HTTP instead of HTTPS)")

    # IP address used instead of a domain name. The old regex missed IPv6 and
    # obfuscated forms (2130706433, 0x7f000001). Hosts made only of numbers are
    # never real domain names, so they are flagged too.
    if _is_ip_host(hostname):
        score_deduction += 30
        flags.append("IP address used instead of domain name")

    # Check length
    if len(url) > 75:
        score_deduction += 10
        flags.append("Unusually long URL")

    # Suspicious keywords
    url_lower = url.lower()
    found_words = [word for word in SUSPICIOUS_WORDS if word in url_lower]
    if found_words:
        score_deduction += 15
        flags.append(f"Suspicious keywords detected: {', '.join(found_words)}")

    return {
        "domain": hostname,
        "deduction": score_deduction,
        "flags": flags,
    }