"""NIST NVD CVE lookup for detected product versions."""
from __future__ import annotations

import re
from typing import Dict, List, Optional

import httpx

from ..config import get_config
from ..limits import limiter
from ..util import UA, log

SEVERITY_DEFAULT = "unknown"


async def lookup(product: str, version: Optional[str] = None,
                 max_results: int = 25) -> List[Dict]:
    """keywordSearch for '<product> <version>' and return CVEs whose
    description mentions the product name (relevance filter)."""
    cfg = get_config()
    product = product.strip()
    if not product:
        return []
    term = f"{product} {version}".strip() if version else product
    try:
        async with limiter("nvd", rate=0.25, burst=1):
            async with httpx.AsyncClient(timeout=cfg.http_timeout, headers={"User-Agent": UA}) as client:
                for attempt in range(3):
                    resp = await client.get(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params={"keywordSearch": term, "resultsPerPage": max_results})
                    if resp.status_code == 503 and attempt < 2:
                        await asyncio_sleep(3)
                        continue
                    resp.raise_for_status()
                    break
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
    except Exception as exc:
        log().debug("NVD lookup %r failed: %r", term, exc)
        return []

    pl = re.escape(product.lower())
    out: List[Dict] = []
    for v in vulns:
        cve = v.get("cve", {})
        desc = " ".join(d.get("value", "") for d in cve.get("descriptions", []))
        # relevance: product name must appear in description or matched cpe names
        if not re.search(rf"(?<![a-z]){pl}", desc.lower()):
            continue
        metrics = (cve.get("metrics") or {}).get("cvssMetricV31") or                   (cve.get("metrics") or {}).get("cvssMetricV2") or []
        cvss = 0.0
        severity = "unknown"
        for m in metrics:
            if "baseScore" in m.get("cvssData", {}):
                cvss = m["cvssData"].get("baseScore", 0.0)
                severity = (m.get("cvssData", {}).get("baseSeverity")
                            or m.get("baseSeverity", "") or "unknown")
                break
        out.append({
            "cve_id": cve.get("id"),
            "cvss": cvss,
            "severity": severity,
            "published": (cve.get("published") or "")[:10],
            "description": desc[:300],
            "matched_product": product,
            "matched_version": version,
        })
    out.sort(key=lambda x: x.get("cvss") or 0, reverse=True)
    return out[:10]


import asyncio as _asyncio


async def asyncio_sleep(s: float):
    await _asyncio.sleep(s)
