"""Have I Been Pwned v3 domain search (requires HIBP_API_KEY)."""
from __future__ import annotations

from typing import Dict, List, Optional

import httpx

from ..config import get_config
from ..limits import limiter
from ..util import UA, log

BASE = "https://haveibeenpwned.com/api/v3"


async def domain_search(domain: str) -> List[Dict]:
    cfg = get_config()
    if not cfg.hibp_key:
        return []
    try:
        async with limiter("hibp", rate=1, burst=2):
            async with httpx.AsyncClient(timeout=cfg.http_timeout, headers={"User-Agent": UA}) as client:
                resp = await client.get(f"{BASE}/domainsearch/{domain}",
                                        headers={"hibp-api-key": cfg.hibp_key})
                if resp.status_code == 404:
                    return []
                if resp.status_code in (401, 403, 429):
                    log().warning("HIBP domainsearch: %s (check key / subscription tier)", resp.status_code)
                    return []
                resp.raise_for_status()
                data = resp.json()
        return data if isinstance(data, list) else []
    except Exception as exc:
        log().debug("HIBP %s failed: %r", domain, exc)
        return []


def classify_pw_exposure(data_classes: List[str]) -> str:
    """plaintext > hashed > none based on DataClasses reported by HIBP."""
    joined = " ".join(data_classes).lower()
    if "plaintext" in joined or "passwords" in joined:
        return "plaintext"
    if "hashed" in joined or "password hashes" in joined:
        return "hashed"
    if any(k in joined for k in ("email addresses", "names", "phone numbers",
                                 "usernames", "dates of birth", "physical addresses")):
        return "none"
    return "unknown"


async def breached_account(email: str) -> List[Dict]:
    """Per-email breach check (requires paid HIBP tier alongside the key)."""
    cfg = get_config()
    if not cfg.hibp_key:
        return []
    try:
        async with limiter("hibp", rate=1, burst=2):
            async with httpx.AsyncClient(timeout=cfg.http_timeout, headers={"User-Agent": UA}) as client:
                resp = await client.get(f"{BASE}/breachedaccount/{email}",
                                        headers={"hibp-api-key": cfg.hibp_key},
                                        params={"truncateResponse": "false"})
                if resp.status_code == 404:
                    return []
                if resp.status_code in (401, 403, 429):
                    return []
                resp.raise_for_status()
                data = resp.json()
        return data if isinstance(data, list) else []
    except Exception:
        return []
