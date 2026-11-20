from urllib.parse import urljoin, urlparse
import dns.resolver
import httpx

SENSITIVE_PATHS = ["/.env", "/.git/config", "/.well-known/security.txt", "/robots.txt"]


async def scan_web_security(url: str) -> dict:
    base_url = url if url.startswith(("http://", "https://")) else f"https://{url}"
    domain = urlparse(base_url).netloc.split(":")[0].lower()
    if domain.startswith("www."):
        domain = domain[4:]

    exposed_files = []
    has_security_txt = False
    flags = []
    deduction = 0

    async with httpx.AsyncClient(timeout=6.0, follow_redirects=False, verify=False) as client:
        for path in SENSITIVE_PATHS:
            target = urljoin(base_url, path)
            try:
                resp = await client.get(target)
                if resp.status_code == 200 and len(resp.text.strip()) > 0:
                    if "security.txt" in path:
                        has_security_txt = True
                    elif path in ("/.env", "/.git/config") and "<html" not in resp.text.lower():
                        exposed_files.append(path)
                        flags.append(f"CRITICAL: Exposed sensitive file at {path}")
                        deduction += 30
            except Exception:
                continue

    has_spf, has_dmarc = False, False
    try:
        for rdata in dns.resolver.resolve(domain, "TXT"):
            if "v=spf1" in rdata.to_text().lower():
                has_spf = True
    except Exception:
        pass

    try:
        for rdata in dns.resolver.resolve(f"_dmarc.{domain}", "TXT"):
            if "v=dmarc1" in rdata.to_text().lower():
                has_dmarc = True
    except Exception:
        pass

    if not has_spf:
        flags.append("Missing SPF DNS record")
        deduction += 5
    if not has_dmarc:
        flags.append("Missing DMARC DNS record")
        deduction += 5

    return {
        "domain": domain,
        "exposed_files": exposed_files,
        "has_security_txt": has_security_txt,
        "dns_security": {"spf": has_spf, "dmarc": has_dmarc},
        "deduction": deduction,
        "flags": flags,
    }