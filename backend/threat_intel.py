import asyncio
import logging
import os

import httpx

# normalize_domain is the SAME function database.py uses when saving reports,
# so lookups always use the same key the reports were stored under.
from database import get_community_reports_db, normalize_domain

log = logging.getLogger(__name__)

# abuse.ch made an Auth-Key mandatory for its APIs on 30 June 2025. Without
# one the old request was rejected, and the bare `except: pass` hid it, so the
# URLhaus check silently never worked. Get a free key at https://auth.abuse.ch
# and set it as the URLHAUS_AUTH_KEY environment variable.
URLHAUS_HOST_URL = os.environ.get("URLHAUS_HOST_URL", "https://urlhaus-api.abuse.ch/v1/host/")

DEDUCT_COMMUNITY = 25
DEDUCT_URLHAUS = 40

_warned_no_key = False


def _make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=6.0)


def _to_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


async def _community_lookup(domain: str):
    """Returns (reports, checked). A database problem must not crash the scan."""
    try:
        return await asyncio.to_thread(get_community_reports_db, domain), True
    except Exception:
        log.exception("Community reports lookup failed")
        return [], False


async def _urlhaus_lookup(domain: str) -> dict:
    """Ask URLhaus about a host. `checked` is False whenever we could NOT get
    a real answer, so "not listed" is never confused with "lookup failed"."""
    global _warned_no_key
    result = {"checked": False, "listed": False, "urls_online": 0, "url_count": 0, "error": None}

    auth_key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    if not auth_key:
        result["error"] = "URLHAUS_AUTH_KEY is not set"
        if not _warned_no_key:
            _warned_no_key = True
            log.warning("URLHAUS_AUTH_KEY is not set: URLhaus lookups are skipped")
        return result

    try:
        async with _make_client() as client:
            resp = await client.post(
                URLHAUS_HOST_URL, data={"host": domain}, headers={"Auth-Key": auth_key}
            )
    except httpx.TimeoutException:
        result["error"] = "URLhaus timed out"
        return result
    except httpx.HTTPError:
        result["error"] = "URLhaus request failed"
        return result

    if resp.status_code in (401, 403):
        result["error"] = "URLhaus rejected the Auth-Key"
        log.error("URLhaus returned %s: check URLHAUS_AUTH_KEY", resp.status_code)
        return result
    if resp.status_code == 429:
        result["error"] = "URLhaus rate limit reached"
        return result
    if resp.status_code != 200:
        result["error"] = f"URLhaus returned HTTP {resp.status_code}"
        return result

    try:
        data = resp.json()
        status = data.get("query_status")
    except (ValueError, AttributeError):
        result["error"] = "URLhaus returned an unreadable response"
        return result

    if status == "ok":  # host is in the database
        result.update(
            checked=True,
            listed=True,
            urls_online=_to_int(data.get("urls_online")),
            url_count=_to_int(data.get("url_count")),
        )
    elif status == "no_results":  # a real answer: host is not listed
        result["checked"] = True
    else:  # "invalid_host" or anything new
        result["error"] = f"URLhaus query status: {str(status)[:40]}"
    return result


async def check_threat_intel(url: str) -> dict:
    flags = []
    deduction = 0

    # Same parsing as database.py. The old `.netloc.split(":")[0]` turned
    # "https://paypal.com:x@evil.com" into "paypal.com", so the lookup checked
    # the WRONG site, and its keys never matched the stored community reports.
    try:
        domain = normalize_domain(url)
    except ValueError:
        return {
            "domain": "",
            "community_reports": [],
            "community_checked": False,
            "urlhaus_listed": False,
            "urlhaus_checked": False,
            "urlhaus_urls_online": 0,
            "urlhaus_error": "Could not read a domain from the URL",
            "deduction": 0,
            "flags": [],
        }

    # The two lookups don't depend on each other, so run them together.
    (community_hits, community_checked), urlhaus = await asyncio.gather(
        _community_lookup(domain), _urlhaus_lookup(domain)
    )

    if community_hits:
        hit = community_hits[0]
        flags.append(f"Flagged by community ({hit['votes']} report(s) for {hit['category']})")
        deduction += DEDUCT_COMMUNITY

    if urlhaus["listed"]:
        online = urlhaus["urls_online"]
        detail = f"{online} URL(s) currently online" if online else "no URLs currently online"
        flags.append(f"Listed in URLhaus malware/phishing database ({detail})")
        deduction += DEDUCT_URLHAUS

    return {
        "domain": domain,
        "community_reports": community_hits,
        "community_checked": community_checked,
        "urlhaus_listed": urlhaus["listed"],
        "urlhaus_checked": urlhaus["checked"],  # False = we could not get an answer
        "urlhaus_urls_online": urlhaus["urls_online"],
        "urlhaus_error": urlhaus["error"],
        "deduction": deduction,
        "flags": flags,
    }