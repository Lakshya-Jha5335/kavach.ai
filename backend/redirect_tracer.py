"""Redirect tracer: follows a URL's redirect chain safely and scores it.

This function fetches URLs chosen by strangers, so it is a classic SSRF
target. The safety rules below are the important part of this file:
  * only http/https is followed
  * every hop's host is resolved and ALL its addresses must be public IPs
  * the request is then pinned to the IP we validated, so DNS can't change
    its answer between our check and the connection (DNS rebinding)
  * response bodies are streamed and capped, and there is an overall deadline
"""
import asyncio
import html
import ipaddress
import logging
import re
import socket
from urllib.parse import unquote, urldefrag, urljoin, urlsplit

import httpx

log = logging.getLogger(__name__)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "rb.gy",
    "cutt.ly", "tiny.cc", "shorturl.at", "rebrand.ly", "buff.ly", "lnkd.in",
    "t.ly", "v.gd", "s.id", "bit.do", "adf.ly", "j.mp", "tr.im", "x.co",
    "soo.gd", "bl.ink",
}

# Free-hosting platforms where every customer gets a subdomain. Two different
# subdomains here are two different sites (this is a small stand-in for the
# Public Suffix List; the `tldextract` library does it exactly).
SHARED_HOSTING = {
    "github.io", "gitlab.io", "vercel.app", "netlify.app", "pages.dev",
    "workers.dev", "web.app", "firebaseapp.com", "herokuapp.com",
    "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com", "glitch.me",
    "repl.co", "replit.app", "onrender.com", "azurewebsites.net",
    "cloudfront.net", "appspot.com", "ngrok.io", "ngrok-free.app",
    "trycloudflare.com", "duckdns.org", "000webhostapp.com",
    "infinityfreeapp.com", "rf.gd", "webflow.io", "carrd.co", "notion.site",
}
# For "example.co.uk"-style domains: 2-letter country code + one of these.
SECOND_LEVEL_LABELS = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "nic", "res"}

# Scoring (edit these to tune the trust score)
LONG_CHAIN_THRESHOLD = 3      # more than this many requests = "excessive"
DEDUCT_LONG_CHAIN = 10
DEDUCT_CROSS_SITE = 15
DEDUCT_SHORTENER = 10
DEDUCT_LOOP = 10
DEDUCT_INTERNAL_REDIRECT = 20

# Limits
MAX_HOPS_LIMIT = 20
MAX_BODY_BYTES = 256 * 1024   # only the start of a page is searched for meta refresh
MAX_URL_LEN = 4096
MAX_META_TAGS = 500
MAX_TAG_LEN = 2048
MAX_IPS_TRIED = 3
TOTAL_TIMEOUT = 20.0          # whole trace, in seconds (httpx timeouts are per-read only)
REDIRECT_CODES = {301, 302, 303, 307, 308}

DEFAULT_HEADERS = {
    # Many sites block or cloak for the default "python-httpx" agent.
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "identity",  # no compression, so no decompression bombs
}

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://")
_NO_SLASH_SCHEME_RE = re.compile(r"^(?:javascript|data|vbscript|file|mailto|tel|sms|about|blob):", re.I)
_HOST_OK_RE = re.compile(r"[a-z0-9_.:\-]+")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")

_META_START_RE = re.compile(r"<meta\b", re.I)
_META_TAG_RE = re.compile(r"""<meta\b((?:[^>"']|"[^"]*"|'[^']*')*)>""", re.I)
_ATTR_RE = re.compile(r"""([^\s"'<>/=]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""")
_REFRESH_RE = re.compile(
    r"""^\s*[\d.]*\s*[;,]?\s*(?:url\s*=\s*)?["']?(?P<url>[^"']*?)["']?\s*$""", re.I | re.S
)


class _Blocked(Exception):
    """A URL we refuse to fetch (unsafe, internal, or not http/https)."""

    def __init__(self, reason: str, internal: bool = False):
        super().__init__(reason)
        self.internal = internal


# --------------------------------------------------------------------------
# URL / host helpers
# --------------------------------------------------------------------------

def _prepare_url(raw: str):
    """Clean the user's input. Returns (url, scheme_was_assumed)."""
    raw = raw.strip().replace("\\", "/")  # browsers treat "\" like "/"
    if not raw:
        raise _Blocked("empty URL")
    if len(raw) > MAX_URL_LEN:
        raise _Blocked("URL too long")
    match = _SCHEME_RE.match(raw)
    if match:  # case-insensitive: "HTTP://..." used to become "https://HTTP://..."
        scheme = match.group(1).lower()
        if scheme not in ("http", "https"):
            raise _Blocked("unsupported URL scheme (only http/https)")
        return scheme + raw[len(scheme):], False
    if _NO_SLASH_SCHEME_RE.match(raw):
        raise _Blocked("unsupported URL scheme (only http/https)")
    return "https://" + raw.lstrip("/"), True


def _resolve_target(base: str, ref: str):
    """Turn a Location header / meta-refresh value into an absolute URL."""
    ref = re.sub(r"[\t\r\n]", "", ref).strip().replace("\\", "/")
    if not ref:
        return None
    try:
        target = urljoin(base, ref)
    except ValueError:
        raise _Blocked("invalid redirect URL")
    if len(target) > MAX_URL_LEN:
        raise _Blocked("redirect URL too long")
    return target


def _ascii_host(host: str) -> str:
    host = unquote(host).rstrip(".").lower()
    if not host:
        raise _Blocked("no host in URL")
    try:
        host = host.encode("idna").decode("ascii")  # lookalike unicode -> punycode
    except UnicodeError:
        raise _Blocked("invalid hostname")
    if not _HOST_OK_RE.fullmatch(host):
        raise _Blocked("invalid hostname")
    return host


def _safe_host(url: str) -> str:
    try:
        host = urlsplit(url).hostname
        return _ascii_host(host) if host else ""
    except (ValueError, _Blocked):
        return ""


def _parse_target(url: str):
    """Split a URL into (scheme, host, port, path_and_query), or raise _Blocked."""
    try:
        parts = urlsplit(url)
        port = parts.port
        host = parts.hostname
    except ValueError:
        raise _Blocked("invalid URL")
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise _Blocked("unsupported URL scheme (only http/https)")
    if not host:
        raise _Blocked("no host in URL")
    host = _ascii_host(host)
    if port is None:
        port = 443 if scheme == "https" else 80
    elif not 1 <= port <= 65535:
        raise _Blocked("invalid port")
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    return scheme, host, port, target


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _visit_key(url: str):
    """Identity of a URL for loop detection (ignores #fragment and host case)."""
    url = urldefrag(url)[0]
    try:
        p = urlsplit(url)
        return (p.scheme.lower(), (p.hostname or "").lower(), p.port, p.path or "/", p.query)
    except ValueError:
        return url


def _is_shortener(host: str) -> bool:
    # also matches "www.bit.ly" etc. The old `domain in SHORTENERS` missed those
    # and anything with a port ("bit.ly:443").
    return any(host == s or host.endswith("." + s) for s in SHORTENERS)


def _site(host: str) -> str:
    """Approximate 'registered domain' so www.example.com == example.com."""
    if not host or _is_ip_literal(host):
        return host
    for suffix in SHARED_HOSTING:
        if host.endswith("." + suffix):
            label = host[: -(len(suffix) + 1)].split(".")[-1]
            return f"{label}.{suffix}"
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL_LABELS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


# --------------------------------------------------------------------------
# SSRF protection
# --------------------------------------------------------------------------

def _is_public_ip(ip) -> bool:
    """True only for addresses that are safe to connect to from our server."""
    if isinstance(ip, ipaddress.IPv6Address):
        # IPv6 forms that hide an IPv4 address (e.g. ::ffff:127.0.0.1)
        embedded = [ip.ipv4_mapped, ip.sixtofour]
        if ip.teredo:
            embedded.extend(ip.teredo)
        if ip in _NAT64:
            embedded.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if any(v4 is not None and not _is_public_ip(v4) for v4 in embedded):
            return False
    return bool(ip.is_global) and not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


async def _resolve_host(host: str, port: int) -> list:
    """Resolve a hostname to IP strings, IPv4 first. Also understands odd
    spellings like 2130706433 or 0x7f.0.0.1 exactly like the OS does."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0].split("%")[0]
        if ip not in ips:
            ips.append(ip)
    ips.sort(key=lambda s: ":" in s)  # IPv4 before IPv6
    return ips


async def _resolve_public_ips(host: str, port: int) -> list:
    ips = await _resolve_host(host, port)
    if not ips:
        raise socket.gaierror("no address found")
    for ip in ips:  # if ANY address is internal, refuse (mixed-record trick)
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            raise _Blocked("unrecognised address", internal=True)
        if not _is_public_ip(addr):
            raise _Blocked("target resolves to a private or internal address", internal=True)
    return ips


# --------------------------------------------------------------------------
# Redirect detection inside a response
# --------------------------------------------------------------------------

def _parse_refresh(content: str):
    """Pull the URL out of '0; url=...' (also handles quotes, ',', no 'url=')."""
    match = _REFRESH_RE.match(content or "")
    url = match.group("url").strip() if match else ""
    return url or None  # "5" alone just reloads the same page: not a redirect


def _strip_comments(text: str) -> str:
    """Remove <!-- ... --> (browsers ignore a <meta> inside a comment). Linear time."""
    out, i = [], 0
    while True:
        start = text.find("<!--", i)
        if start == -1:
            out.append(text[i:])
            break
        out.append(text[i:start])
        end = text.find("-->", start + 4)
        if end == -1:
            break  # unterminated comment: the rest is a comment
        i = end + 3
    return "".join(out)


def _find_meta_refresh(text: str):
    """Find <meta http-equiv="refresh" content="0;url=..."> in any attribute
    order, with any quoting. The old regex needed http-equiv BEFORE content,
    so <meta content=... http-equiv=...> slipped straight past it."""
    text = _strip_comments(text)
    for count, start in enumerate(_META_START_RE.finditer(text)):
        if count >= MAX_META_TAGS:
            break
        tag = _META_TAG_RE.match(text, start.start(), start.start() + MAX_TAG_LEN)
        if not tag:
            continue
        attrs = {}
        for a in _ATTR_RE.finditer(tag.group(1)):
            value = a.group(2) if a.group(2) is not None else (
                a.group(3) if a.group(3) is not None else a.group(4)
            )
            attrs.setdefault(a.group(1).lower(), value)
        if attrs.get("http-equiv", "").strip().lower() == "refresh":
            target = _parse_refresh(html.unescape(attrs.get("content", "")))
            if target:
                return target
    return None


async def _read_capped(resp) -> str:
    """Read at most MAX_BODY_BYTES of the body (the old code downloaded all of it)."""
    chunks, size = [], 0
    async for chunk in resp.aiter_bytes():
        chunks.append(chunk)
        size += len(chunk)
        if size >= MAX_BODY_BYTES:
            break
    data = b"".join(chunks)[:MAX_BODY_BYTES]
    try:
        return data.decode(resp.charset_encoding or "utf-8", errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


async def _inspect_response(resp, url: str, hop: dict):
    """Record the status and return the next URL to follow (None = final page)."""
    hop["status_code"] = resp.status_code

    location = resp.headers.get("location")
    if resp.status_code in REDIRECT_CODES and location:
        return _resolve_target(url, location)

    refresh = resp.headers.get("refresh")  # the HTTP-header form of meta refresh
    if refresh:
        target = _parse_refresh(refresh)
        if target:
            return _resolve_target(url, target)

    content_type = resp.headers.get("content-type", "").lower()
    if content_type and "html" not in content_type:
        return None

    target = _find_meta_refresh(await _read_capped(resp))
    return _resolve_target(url, target) if target else None


# --------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------

def _make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(8.0, connect=5.0),
        # verify=False on purpose: phishing sites often have bad certificates
        # and we still want to trace them. We send no credentials or cookies
        # of ours, so there is nothing to steal.
        verify=False,
        headers=DEFAULT_HEADERS,
        # no keep-alive: every hop gets a fresh connection, so a reused HTTPS
        # connection can never carry the wrong server name (SNI) to a new host
        limits=httpx.Limits(max_keepalive_connections=0),
        # never route through an environment proxy: that would bypass the
        # address checks above
        trust_env=False,
    )


async def _do_hop(client, url: str, hop: dict):
    """Fetch one URL safely. Returns the next URL to follow, or None."""
    scheme, host, port, target = _parse_target(url)
    ips = await _resolve_public_ips(host, port)

    default_port = 443 if scheme == "https" else 80
    host_header = f"[{host}]" if ":" in host else host
    if port != default_port:
        host_header += f":{port}"
    extensions = {}
    if scheme == "https" and not _is_ip_literal(host):
        extensions["sni_hostname"] = host

    last_error = None
    for ip in ips[:MAX_IPS_TRIED]:  # e.g. skip an unreachable IPv6 address
        netloc = f"[{ip}]" if ":" in ip else ip
        # Connect to the IP we just validated (not the hostname), keep the
        # real name in the Host header / TLS server name.
        pinned = f"{scheme}://{netloc}:{port}{target}"
        try:
            async with client.stream(
                "GET", pinned, headers={"Host": host_header}, extensions=extensions
            ) as resp:
                return await _inspect_response(resp, url, hop)
        except (httpx.ConnectError, httpx.ConnectTimeout) as e:
            last_error = e
    raise last_error


def _describe_error(e: Exception) -> str:
    """Short, safe message. str(e) is often empty (timeouts) and can leak
    details about our internal network, so we never return it."""
    if isinstance(e, httpx.TimeoutException):
        return "Timed out"
    if isinstance(e, socket.gaierror):
        return "DNS lookup failed"
    if isinstance(e, httpx.ConnectError):
        return "Connection failed"
    if isinstance(e, httpx.ProtocolError):
        return "Invalid response from server"
    if isinstance(e, httpx.InvalidURL):
        return "Invalid URL"
    return "Request failed"


def _new_hop(url: str) -> dict:
    host = _safe_host(url)
    # Every hop has the same keys (the old error/loop hops were missing
    # some, which breaks code that reads hop["domain"]).
    return {
        "url": url,
        "domain": host,
        "status_code": None,
        "is_shortener": _is_shortener(host),
        "error": None,
    }


async def _walk(client, start: str, max_hops: int, hops: list, state: dict):
    current = start
    visited = set()
    remaining = max_hops
    while remaining > 0:
        key = _visit_key(current)
        hop = _new_hop(current)
        if key in visited:
            hop["status"] = "LOOP_DETECTED"
            hops.append(hop)
            state["loop"] = True
            return
        visited.add(key)
        hops.append(hop)

        try:
            nxt = await _do_hop(client, current, hop)
        except _Blocked as e:
            hop["error"] = f"Blocked: {e}"
            if e.internal and len(hops) > 1:
                state["internal_redirect"] = True
            elif len(hops) == 1:
                state["notes"].append(f"URL not fetched: {e}")
            else:
                state["notes"].append(f"Redirect target not followed: {e}")
            return
        except (httpx.HTTPError, httpx.InvalidURL, OSError) as e:
            if (
                state["assumed_scheme"]
                and len(hops) == 1
                and current.startswith("https://")
                and isinstance(e, (httpx.ConnectError, httpx.ConnectTimeout))
            ):
                # The user typed no scheme and https failed to connect: the
                # site may be http-only, so try that once.
                state["assumed_scheme"] = False
                hops.pop()
                visited.discard(key)
                current = "http://" + current[len("https://"):]
                continue
            hop["error"] = _describe_error(e)
            state["notes"].append(f"Could not reach {hop['domain'] or 'host'}: {hop['error']}")
            return
        except Exception:
            log.exception("Unexpected error while tracing a hop to %s", hop["domain"])
            hop["error"] = "Unexpected error"
            state["notes"].append(f"Could not check {hop['domain'] or 'host'}: unexpected error")
            return

        remaining -= 1
        if nxt is None:
            return
        current = nxt

    state["truncated"] = True  # ran out of hops while still being redirected


def _build_result(start: str, hops: list, state: dict, max_hops: int) -> dict:
    real_hops = [h for h in hops if h.get("status") != "LOOP_DETECTED"]
    hostnames = list(dict.fromkeys(h["domain"] for h in hops if h["domain"]))
    sites = list(dict.fromkeys(_site(h) for h in hostnames))

    flags = []
    deduction = 0

    if len(real_hops) > LONG_CHAIN_THRESHOLD:
        flags.append(f"Excessive redirect chain ({len(real_hops)} hops)")
        deduction += DEDUCT_LONG_CHAIN
    if len(sites) > 1:  # compares sites, so example.com -> www.example.com is NOT flagged
        flags.append(f"Cross-domain redirect: {' -> '.join(hostnames)}")
        deduction += DEDUCT_CROSS_SITE
    if any(h["is_shortener"] for h in hops):
        flags.append("Uses URL shortener")
        deduction += DEDUCT_SHORTENER
    if state["loop"]:
        flags.append("Redirect loop detected")
        deduction += DEDUCT_LOOP
    if state["internal_redirect"]:
        flags.append("Redirects to a private or internal address")
        deduction += DEDUCT_INTERNAL_REDIRECT
    if state["truncated"]:
        flags.append(f"Redirect chain cut off after {max_hops} hops; final destination not verified")
    flags.extend(state["notes"])

    return {
        "initial_url": hops[0]["url"] if hops else start,
        "final_url": hops[-1]["url"] if hops else start,
        "hop_count": len(real_hops),
        "hops": hops,
        "truncated": state["truncated"],
        "deduction": deduction,
        "flags": flags,
    }


async def trace_redirects(url: str, max_hops: int = 10) -> dict:
    try:
        max_hops = max(1, min(int(max_hops), MAX_HOPS_LIMIT))
    except (TypeError, ValueError):
        max_hops = 10

    hops = []
    state = {
        "loop": False,
        "truncated": False,
        "internal_redirect": False,
        "assumed_scheme": False,
        "notes": [],
    }

    raw = url.strip() if isinstance(url, str) else ""
    try:
        start, state["assumed_scheme"] = _prepare_url(raw)
    except _Blocked as e:
        start = raw[:MAX_URL_LEN]
        hop = _new_hop(start)
        hop["error"] = f"Blocked: {e}"
        hops.append(hop)
        state["notes"].append(f"URL not fetched: {e}")
        return _build_result(start, hops, state, max_hops)

    async with _make_client() as client:
        try:
            await asyncio.wait_for(
                _walk(client, start, max_hops, hops, state), timeout=TOTAL_TIMEOUT
            )
        except asyncio.TimeoutError:
            if hops and not hops[-1]["error"]:
                hops[-1]["error"] = "Timed out (overall time limit reached)"
            state["notes"].append("Trace stopped: overall time limit reached")

    return _build_result(start, hops, state, max_hops)