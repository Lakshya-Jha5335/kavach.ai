import socket
import ssl
import time


def _strip_port(domain: str) -> str:
    """Return just the host. The old domain.split(":")[0] turned IPv6
    addresses like "::1" into an empty string."""
    domain = (domain or "").strip()
    if domain.startswith("["):  # "[::1]:443"
        return domain[1:].split("]")[0]
    if domain.count(":") == 1:  # "example.com:8443"
        return domain.split(":")[0]
    return domain  # plain hostname or bare IPv6


def _flatten_name(name) -> dict:
    """A cert's issuer/subject is a tuple of RDNs, each a tuple of (key, value)
    pairs. The old code only read the first pair of each RDN."""
    return {key: value for rdn in (name or ()) for key, value in rdn}


def _failure(hostname: str, issuer: str, deduction: int, flag: str) -> dict:
    return {
        "valid": False,
        "issuer": issuer,
        "common_name": hostname,
        "days_until_expiry": 0,
        "deduction": deduction,
        "flags": [flag],
    }

def check_tls(domain: str) -> dict:
    hostname = _strip_port(domain)

    # create_connection(("", 443)) would quietly connect to this machine itself.
    if not hostname:
        return _failure("", "None / Unreachable", 30, "No hostname provided for TLS check")

    context = ssl.create_default_context()

    # Only the network part sits inside try/except. Before, a bug while parsing
    # the certificate was reported as "Could not establish TLS connection".
    try:
        with socket.create_connection((hostname, 443), timeout=5.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert() or {}
    except ssl.SSLCertVerificationError as e:
        return _failure(
            hostname,
            "Untrusted / Invalid",
            40,
            f"SSL Verification Failed: {str(e)}",
        )
    except Exception as e:
        return _failure(
            hostname,
            "None / Unreachable",
            30,
            f"Could not establish TLS connection: {str(e)}",
        )

    issuer = _flatten_name(cert.get("issuer"))
    subject = _flatten_name(cert.get("subject"))
    san_dns = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]

    # Expiry: ssl.cert_time_to_seconds is locale-independent. The old strptime
    # with %b breaks on non-English system locales.
    days_left = None
    not_after = cert.get("notAfter")
    if not_after:
        try:
            days_left = int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)
        except ValueError:
            pass

    return {
        "valid": True,
        # Some CAs have no organizationName, so fall back to their common name.
        "issuer": issuer.get("organizationName") or issuer.get("commonName") or "Unknown CA",
        # Modern certs often have no subject CN, only SANs.
        "common_name": subject.get("commonName") or (san_dns[0] if san_dns else hostname),
        "days_until_expiry": days_left,
        "deduction": 0,
        "flags": [],
    }