from datetime import datetime, timezone
from urllib.parse import urlparse
import httpx


async def check_ct_logs(url: str) -> dict:
    domain = urlparse(url if "://" in url else f"https://{url}").netloc.split(":")[0].lower()
    if domain.startswith("www."):
        domain = domain[4:]

    ct_url = f"https://crt.sh/?q={domain}&output=json"
    flags = []
    deduction = 0

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(ct_url)
            if resp.status_code != 200:
                return {"domain": domain, "status": "unavailable", "deduction": 0, "flags": []}
            entries = resp.json()
    except Exception as e:
        return {"domain": domain, "status": "error", "error": str(e), "deduction": 0, "flags": []}

    if not entries:
        return {
            "domain": domain,
            "total_certs_logged": 0,
            "deduction": 15,
            "flags": ["No Certificate Transparency logs found"],
        }

    entries.sort(key=lambda x: x.get("entry_timestamp", ""), reverse=True)
    latest = entries[0]
    issuer = latest.get("issuer_name", "Unknown")
    not_before = latest.get("not_before", "")

    cert_age_days = None
    if not_before:
        try:
            issued_dt = datetime.fromisoformat(not_before).replace(tzinfo=timezone.utc)
            cert_age_days = (datetime.now(timezone.utc) - issued_dt).days
            if cert_age_days < 7:
                flags.append(f"Very newly issued certificate ({cert_age_days} days old)")
                deduction += 20
        except ValueError:
            pass

    return {
        "domain": domain,
        "total_certs_logged": len(entries),
        "latest_issuer": issuer,
        "latest_not_before": not_before,
        "cert_age_days": cert_age_days,
        "deduction": deduction,
        "flags": flags,
    }