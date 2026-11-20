import ipaddress
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

# Anchored to THIS file, not the current working directory, so starting the
# server from a different folder can't silently create a second, empty DB.
# Set the KAVACH_DB_PATH environment variable to override it (for example,
# to point at a persistent disk on your hosting provider).
DB_PATH = os.environ.get("KAVACH_DB_PATH") or str(Path(__file__).resolve().parent / "kavach.db")

MAX_NOTES_LEN = 500
MAX_CATEGORY_LEN = 50
MAX_VERDICT_LEN = 100
MAX_URL_LEN = 2048

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_HOST_RE = re.compile(r"[a-z0-9_.-]+")
_NUM_PART_RE = re.compile(r"0[xX][0-9a-fA-F]*|[0-9]+")


@contextmanager
def get_conn():
    """Open a connection, commit on success, roll back on error, and ALWAYS close it.

    Note: `with sqlite3.connect(...) as conn` only commits/rolls back; it does
    NOT close the connection, so every call used to leak one.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10)  # wait up to 10s if DB is locked
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _with_scheme(raw: str) -> str:
    """Make sure the text starts with a real scheme so urlsplit finds the host.

    - Backslashes become slashes, because browsers treat "\\" like "/" but
      Python doesn't ("https://evil.com\\@paypal.com" goes to evil.com).
    - Only a real "scheme://" at the START counts. The old `"://" in raw`
      check also matched "://" inside a query string.
    """
    raw = raw.strip().replace("\\", "/")
    if _SCHEME_RE.match(raw):
        return raw
    return "https://" + raw.lstrip("/")


def _normalize_ip(host: str):
    """Return the canonical form of an IP address, or None if host isn't one.

    Handles the obfuscated IPv4 spellings browsers accept (decimal
    "2130706433", hex "0x7f.0.0.1", octal "0177.0.0.1", short "127.1"), so
    every spelling of one IP maps to ONE stored value.
    """
    if ":" in host:  # IPv6
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            return None

    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or not all(_NUM_PART_RE.fullmatch(p) for p in parts):
        return None

    nums = []
    for p in parts:
        if p[:2] in ("0x", "0X"):
            n = int(p[2:] or "0", 16)
        elif len(p) > 1 and p[0] == "0":
            try:
                n = int(p, 8)
            except ValueError:  # e.g. "089" is not valid octal
                return None
        else:
            n = int(p)
        nums.append(n)

    *head, last = nums
    if any(n > 255 for n in head) or last >= 256 ** (5 - len(nums)):
        return None
    value = last + sum(n << (8 * (3 - i)) for i, n in enumerate(head))
    return str(ipaddress.IPv4Address(value))


def normalize_domain(url_or_domain: str) -> str:
    """Turn a URL or bare domain into one clean, lowercase host string.

    Uses `.hostname` (not `.netloc`) so ports, usernames and passwords are
    handled correctly: "https://paypal.com:x@evil.com" is evil.com.

    Raises ValueError if no valid host can be found.
    """
    raw = (url_or_domain or "").strip()
    if not raw:
        raise ValueError("A URL or domain is required")

    try:
        host = urlsplit(_with_scheme(raw)).hostname
    except ValueError as e:  # e.g. malformed IPv6 like "http://[::1"
        raise ValueError(f"Invalid URL: {raw!r}") from e

    host = unquote(host or "").rstrip(".")  # browsers decode "%65vil.com" too
    if not host:
        raise ValueError(f"Could not find a domain in: {raw!r}")

    ip = _normalize_ip(host)
    if ip:
        return ip

    try:
        # Store lookalike unicode domains as punycode (xn--...) so they
        # can't be visually confused with the real ASCII domain.
        host = host.encode("idna").decode("ascii")
    except UnicodeError as e:  # empty label ("a..b"), label too long, etc.
        raise ValueError(f"Invalid domain: {host!r}") from e

    host = host.lower()
    if len(host) > 253 or "." not in host or not _HOST_RE.fullmatch(host):
        raise ValueError(f"Invalid domain: {host!r}")
    return host


def clean_url(url: str) -> str:
    """Strip the parts of a URL that can hold secrets before we store it.

    Removes the query string (?token=...), the fragment (#...) and any
    username:password@ part. Scheme, host and path are kept as typed.
    """
    raw = (url or "").strip().replace("\\", "/")
    raw = re.split(r"[?#]", raw, maxsplit=1)[0]
    match = _SCHEME_RE.match(raw)
    prefix = match.group(0) if match else ""
    authority, slash, path = raw[len(prefix):].partition("/")
    authority = authority.rpartition("@")[2]
    return f"{prefix}{authority}{slash}{path}"[:MAX_URL_LEN]


def init_db():
    with get_conn() as conn:
        # WAL lets readers and a writer work at the same time
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                trust_score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                flags TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS community_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                url TEXT NOT NULL,
                category TEXT NOT NULL,
                notes TEXT,
                votes INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)


def _json_default(obj):
    """Let json.dumps handle sets and other odd flag types instead of crashing
    (a set becomes a sorted list; anything else becomes its string form)."""
    if isinstance(obj, (set, frozenset)):
        return sorted(obj, key=str)
    return str(obj)


def save_scan(url: str, trust_score: int, verdict: str, flags: list):
    url = clean_url(url)
    if not url:
        raise ValueError("A URL is required")
    trust_score = max(0, min(100, int(trust_score)))  # keep it in 0-100
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO scans (url, trust_score, verdict, flags, created_at) VALUES (?, ?, ?, ?, ?)",
            (
                url,
                trust_score,
                str(verdict)[:MAX_VERDICT_LEN],
                json.dumps(flags or [], default=_json_default),
                _now(),
            ),
        )


def _load_flags(text) -> list:
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return []
    return value if isinstance(value, list) else []


def get_recent_scans_db(limit: int = 10) -> list:
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 10
    # A negative LIMIT in SQLite means "no limit", so clamp it
    limit = max(1, min(limit, 100))
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [
        {
            "id": r["id"],
            "url": r["url"],
            "trust_score": r["trust_score"],
            "verdict": r["verdict"],
            "flags": _load_flags(r["flags"]),
            "created_at": r["created_at"],
        }
        for r in rows
    ]


def report_threat_db(url: str, category: str, notes: str = "") -> dict:
    domain = normalize_domain(url)
    category = (category or "").strip()[:MAX_CATEGORY_LEN]
    if not category:
        raise ValueError("A category is required")
    notes = (notes or "").strip()[:MAX_NOTES_LEN]

    with get_conn() as conn:
        # One atomic statement: insert a new report, or add a vote if the
        # domain already exists. The old "SELECT then INSERT" could crash with
        # IntegrityError (or lose votes) when two requests arrived together.
        conn.execute(
            """
            INSERT INTO community_reports (domain, url, category, notes, votes, created_at)
            VALUES (?, ?, ?, ?, 1, ?)
            ON CONFLICT(domain) DO UPDATE SET votes = votes + 1
            """,
            (domain, clean_url(url), category, notes, _now()),
        )
        votes = conn.execute(
            "SELECT votes FROM community_reports WHERE domain = ?", (domain,)
        ).fetchone()["votes"]

    return {
        "status": "reported" if votes == 1 else "upvoted",
        "domain": domain,
        "votes": votes,
    }


def get_community_reports_db(domain: str) -> list:
    try:
        domain = normalize_domain(domain)  # accepts a URL or a bare domain
    except ValueError:
        return []
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT category, votes, notes FROM community_reports WHERE domain = ?",
            (domain,),
        ).fetchall()
    return [dict(r) for r in rows]