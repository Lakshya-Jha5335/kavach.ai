import asyncio
import ipaddress
import logging
import os
import socket
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Existing scanners in backend/
from header_scanner import scan_headers
from tls_checker import check_tls
from url_analyser import analyze_url

# New SQLite persistence and threat detection modules
from database import get_recent_scans_db, init_db, report_threat_db, save_scan
from redirect_tracer import trace_redirects
from ct_monitor import check_ct_logs
from vuln_scanner import scan_web_security
from content_scanner import analyze_page_content
from threat_intel import check_threat_intel

logger = logging.getLogger("kavach")

# Points deducted from the trust score when a check crashes (so a failed
# check never makes a site look safer than it is). Tune as you like.
CHECK_FAILURE_DEDUCTION = 10

app = FastAPI(title="kavach.ai Threat Intelligence API")


@app.on_event("startup")
def startup_event() -> None:
    init_db()


# Comma-separated list in .env, e.g. CORS_ORIGINS=http://localhost:5173,https://kavach.ai
# Defaults to "*" for development.
origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    # "*" origins combined with credentials=True is invalid per the CORS spec
    # and browsers reject it. This API uses no cookies, so credentials are off.
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str


class ReportRequest(BaseModel):
    url: str
    category: str
    notes: str = ""


def normalize_url(raw: str) -> str:
    """Clean user input into an http(s) URL or raise a 400."""
    url = raw.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    # Case-insensitive scheme handling. The old startswith() check turned
    # "HTTP://x.com" into "https://HTTP://x.com" and "ftp://x" into "https://ftp://x".
    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid URL provided")

    if parsed.scheme.lower() not in ("http", "https") or not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL provided")

    return url


def _resolves_to_public_ip_only(hostname: str) -> bool | None:
    """True if every resolved IP is public, False if any is private/internal, None if the name doesn't resolve.
    Blocking call: run it in a thread."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, UnicodeError):
        return None

    for info in infos:
        ip_str = info[4][0].split("%")[0]  # strip IPv6 scope id
        try:
            if not ipaddress.ip_address(ip_str).is_global:
                return False
        except ValueError:
            return False

    return True


async def ensure_public_host(hostname: str) -> None:
    """SSRF guard: this endpoint makes server-side requests to user-supplied URLs,
    so refuse localhost, private ranges and cloud metadata addresses."""
    result = await asyncio.to_thread(_resolves_to_public_ip_only, hostname)
    if result is None:
        raise HTTPException(status_code=400, detail="Domain could not be resolved")
    if result is False:
        raise HTTPException(
            status_code=400,
            detail="Scanning private or internal addresses is not allowed",
        )


def safe_result(name: str, result) -> dict:
    """If a check raised, log it and return a fallback instead of a 500."""
    if isinstance(result, BaseException):
        logger.error("%s check failed: %r", name, result)
        return {
            "deduction": CHECK_FAILURE_DEDUCTION,
            "flags": [f"{name} check could not be completed"],
            "error": True,
        }
    return result


async def _run_maybe_async(func, *args):
    """Run coroutine functions directly and sync blocking functions in a worker thread."""
    if asyncio.iscoroutinefunction(func):
        return await func(*args)
    return await asyncio.to_thread(func, *args)


@app.post("/api/scan")
async def scan_website(request: ScanRequest):
    target_url = normalize_url(request.url)
    try:
        url_res = await _run_maybe_async(analyze_url, target_url)
    except HTTPException:
        raise
    except Exception:
        logger.exception("analyze_url failed")
        raise HTTPException(status_code=400, detail="Invalid URL provided")

    if not isinstance(url_res, dict):
        raise HTTPException(status_code=500, detail="Invalid URL analysis output")

    domain = url_res.get("domain")
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid URL provided")

    hostname = urlparse(target_url).hostname
    await ensure_public_host(hostname)

    # Run independent checks concurrently without blocking the event loop.
    (
        tls_raw,
        header_raw,
        redirect_raw,
        ct_raw,
        vuln_raw,
        content_raw,
        intel_raw,
    ) = await asyncio.gather(
        _run_maybe_async(check_tls, domain),
        _run_maybe_async(scan_headers, target_url),
        _run_maybe_async(trace_redirects, target_url),
        _run_maybe_async(check_ct_logs, target_url),
        _run_maybe_async(scan_web_security, target_url),
        _run_maybe_async(analyze_page_content, target_url),
        _run_maybe_async(check_threat_intel, target_url),
        return_exceptions=True,
    )

    tls_res = safe_result("TLS certificate", tls_raw)
    header_res = safe_result("Security headers", header_raw)
    redirect_res = safe_result("Redirect chain", redirect_raw)
    ct_res = safe_result("Certificate Transparency", ct_raw)
    vuln_res = safe_result("Web security", vuln_raw)
    content_res = safe_result("AI content analysis", content_raw)
    intel_res = safe_result("Threat intelligence", intel_raw)

    all_modules = (
        url_res,
        tls_res,
        header_res,
        redirect_res,
        ct_res,
        vuln_res,
        content_res,
        intel_res,
    )

    total_deduction = sum(
        r.get("deduction", 0) for r in all_modules if isinstance(r, dict)
    )
    trust_score = max(0, min(100, 100 - total_deduction))

    if trust_score >= 80:
        verdict = "Safe"
    elif trust_score >= 50:
        verdict = "Suspicious"
    else:
        verdict = "High Risk"

    all_flags = [
        flag
        for r in all_modules
        if isinstance(r, dict)
        for flag in (r.get("flags") or [])
    ]

    # Persist scan history in local SQLite; DB errors never fail a scan response.
    try:
        await asyncio.to_thread(save_scan, target_url, trust_score, verdict, all_flags)
    except Exception as e:
        logger.warning("SQLite insert warning: %s", e)

    return {
        "url": target_url,
        "trust_score": trust_score,
        "verdict": verdict,
        "flags": all_flags,
        "details": {
            "url_analysis": url_res,
            "tls_certificate": tls_res,
            "security_headers": header_res,
            "redirects": redirect_res,
            "certificate_transparency": ct_res,
            "web_security": vuln_res,
            "content_ai": content_res,
            "threat_intel": intel_res,
        },
    }


@app.post("/api/report")
async def submit_community_report(req: ReportRequest):
    target_url = normalize_url(req.url)
    category = req.category.strip()
    if not category:
        raise HTTPException(status_code=400, detail="Category is required")

    try:
        return await asyncio.to_thread(
            report_threat_db, target_url, category, req.notes.strip()
        )
    except Exception as e:
        logger.warning("SQLite report warning: %s", e)
        raise HTTPException(status_code=500, detail="Could not save community report")


@app.get("/api/recent-scans")
def get_recent_scans():
    # Plain `def`: FastAPI runs sync routes in a worker threadpool.
    try:
        return get_recent_scans_db(10)
    except Exception as e:
        logger.warning("SQLite fetch warning: %s", e)
        return []