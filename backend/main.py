import asyncio
import ipaddress
import logging
import os
import socket
from typing import Optional
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from supabase import Client, create_client

from header_scanner import scan_headers
from tls_checker import check_tls
from url_analyzer import analyze_url

load_dotenv()

logger = logging.getLogger("kavach")

# Points deducted from the trust score when a check crashes (so a failed
# check never makes a site look safer than it is). Tune as you like.
CHECK_FAILURE_DEDUCTION = 10

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# A bad key/URL used to crash the whole app at import time. Now it just
# disables DB features and the scanner keeps working.
supabase: Optional[Client] = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as e:
        logger.warning("Supabase client could not be created: %s", e)

app = FastAPI(title="kavach.ai Threat Intelligence API")

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


def _resolves_to_public_ip_only(hostname: str) -> Optional[bool]:
    """True if every resolved IP is public, False if any is private/internal,
    None if the name doesn't resolve. Blocking call: run it in a thread."""
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
    """SSRF guard: this endpoint makes server-side requests to user-supplied
    URLs, so refuse localhost, private ranges and cloud metadata addresses."""
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


@app.post("/api/scan")
async def scan_website(request: ScanRequest):
    target_url = normalize_url(request.url)

    try:
        url_res = analyze_url(target_url)
    except Exception:
        logger.exception("analyze_url failed")
        raise HTTPException(status_code=400, detail="Invalid URL provided")

    domain = url_res.get("domain")
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid URL provided")

    await ensure_public_host(urlparse(target_url).hostname)

    # check_tls is a blocking (socket) call, so it runs in a worker thread to
    # keep the event loop free. Both checks are independent, so run them together.
    tls_raw, header_raw = await asyncio.gather(
        asyncio.to_thread(check_tls, domain),
        scan_headers(target_url),
        return_exceptions=True,
    )
    tls_res = safe_result("TLS certificate", tls_raw)
    header_res = safe_result("Security headers", header_raw)

    total_deduction = sum(
        r.get("deduction", 0) for r in (url_res, tls_res, header_res)
    )
    trust_score = max(0, 100 - total_deduction)

    if trust_score >= 80:
        verdict = "Safe"
    elif trust_score >= 50:
        verdict = "Suspicious"
    else:
        verdict = "High Risk"

    all_flags = (
        list(url_res.get("flags") or [])
        + list(tls_res.get("flags") or [])
        + list(header_res.get("flags") or [])
    )

    # Save result to Supabase. The client is synchronous, so run it in a thread;
    # DB problems must never crash a scan.
    if supabase:
        record = {
            "url": target_url,
            "trust_score": trust_score,
            "verdict": verdict,
            "flags": all_flags,
        }
        try:
            await asyncio.to_thread(
                lambda: supabase.table("scans").insert(record).execute()
            )
        except Exception as e:
            logger.warning("Supabase insert warning: %s", e)

    return {
        "url": target_url,
        "trust_score": trust_score,
        "verdict": verdict,
        "flags": all_flags,
        "details": {
            "url_analysis": url_res,
            "tls_certificate": tls_res,
            "security_headers": header_res,
        },
    }


@app.get("/api/recent-scans")
def get_recent_scans():
    # Plain `def`: FastAPI runs it in a threadpool, so the blocking Supabase
    # call doesn't stall the event loop.
    if not supabase:
        return []
    try:
        response = (
            supabase.table("scans")
            .select("*")
            .order("created_at", desc=True)
            .limit(10)
            .execute()
        )
        return response.data
    except Exception as e:
        logger.warning("Supabase fetch warning: %s", e)
        return []