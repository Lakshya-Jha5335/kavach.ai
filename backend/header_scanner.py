import asyncio
import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import httpx

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
]

PER_HEADER_DEDUCTION = 5
FETCH_FAILURE_DEDUCTION = 20
MAX_REDIRECTS = 5
REQUEST_TIMEOUT = 5.0  # per network operation (connect / read / ...)
TOTAL_TIMEOUT = 10.0   # hard cap for the whole scan, redirects included

# Some sites answer 403 to the default "python-httpx" user agent, and the
# headers on that block page say nothing about the real site.
USER_AGENT = "Mozilla/5.0 (compatible; kavach.ai-scanner/1.0)"


class _ScanError(Exception):
    """An expected failure. The message is shown to the user as the flag."""


def _host_is_public(hostname: str) -> bool:
    """Blocking. True only if the name resolves and every address is public."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, UnicodeError):
        return False

    for info in infos:
        ip_str = info[4][0].split("%")[0]  # strip IPv6 scope id
        try:
            if not ipaddress.ip_address(ip_str).is_global:
                return False
        except ValueError:
            return False
    return bool(infos)


async def _fetch(url: str):
    """GET the url and return (status_code, headers, final_url).

    Redirects are followed by hand so every hop is checked. With
    follow_redirects=True a public site could answer "302 -> http://169.254.169.254/"
    and get around the private-address check done before the scan starts.
    """
    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            parsed = urlparse(current)
            host = parsed.hostname
            if parsed.scheme not in ("http", "https") or not host:
                raise _ScanError(f"Request blocked: invalid or unsupported URL ({current[:100]})")

            if not await asyncio.to_thread(_host_is_public, host):
                raise _ScanError(
                    f"Request blocked: {host} is a private, internal or unresolvable address"
                )

            # stream() reads only the headers. client.get() downloaded the entire
            # body first, so a huge or endless response could hang or exhaust memory.
            async with client.stream("GET", current) as response:
                if response.has_redirect_location:
                    current = urljoin(current, response.headers["location"])
                    continue
                return response.status_code, httpx.Headers(response.headers), current

        raise _ScanError(f"Failed to fetch headers: too many redirects (more than {MAX_REDIRECTS})")


def _failure(flag: str) -> dict:
    return {
        "status_code": None,
        "final_url": None,
        "deduction": FETCH_FAILURE_DEDUCTION,
        "flags": [flag],
    }


async def scan_headers(url: str) -> dict:
    # httpx's timeout is per operation, so a server that drips data slowly could
    # keep the old version waiting almost forever. This is a hard overall limit.
    try:
        status_code, headers, final_url = await asyncio.wait_for(
            _fetch(url), timeout=TOTAL_TIMEOUT
        )
    except _ScanError as e:
        return _failure(str(e))
    except asyncio.TimeoutError:
        return _failure(f"Failed to fetch headers: timed out after {TOTAL_TIMEOUT:g}s")
    except Exception as e:
        # str(e) is empty for many httpx errors (e.g. ReadTimeout), which used to
        # produce the useless message "Failed to fetch headers: ".
        detail = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
        return _failure(f"Failed to fetch headers: {detail}")

    missing = []
    deduction = 0
    for header in SECURITY_HEADERS:
        # httpx.Headers is already case-insensitive. An empty value counts as
        # missing because a blank header protects nothing.
        if not (headers.get(header) or "").strip():
            missing.append(f"Missing {header}")
            deduction += PER_HEADER_DEDUCTION

    return {
        "status_code": status_code,
        "final_url": final_url,
        "deduction": deduction,
        "flags": missing,
    }