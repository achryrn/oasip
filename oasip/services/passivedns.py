"""Passive DNS aggregation: SecurityTrails, VirusTotal, HackerTarget, and
various passive sources. Every integration is optional and degrades to [].
"""
from __future__ import annotations

from typing import Dict, List

import httpx

from ..config import get_config
from ..limits import limiter
from ..util import UA, log


async def _get(url: str, headers: Dict, rate: float, timeout: float) -> Dict:
    try:
        async with limiter("passivedns", rate=rate, burst=4):
            async with httpx.AsyncClient(timeout=timeout, headers={"User-Agent": UA}) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 429:
                    log().warning("passive DNS rate limited: %s", url)
                    return {}
                resp.raise_for_status()
                return resp.json()
    except Exception as exc:
        log().debug("passive DNS %s failed: %r", url, exc)
        return {}


async def securitytrails(domain: str) -> List[str]:
    cfg = get_config()
    if not cfg.securitytrails_key:
        return []
    data = await _get(
        f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
        {"APIKEY": cfg.securitytrails_key}, 60 / 60, cfg.http_timeout)
    subs = data.get("subdomains") or []
    return [f"{s}.{domain}" for s in subs if isinstance(s, str)]


async def virustotal(domain: str) -> List[str]:
    cfg = get_config()
    if not cfg.virustotal_key:
        return []
    data = await _get(
        f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=200",
        {"x-apikey": cfg.virustotal_key}, 500 / 86400, cfg.http_timeout)
    out = []
    for item in (data.get("data") or []):
        host = (item.get("id") or "")
        if host:
            out.append(host)
    return out


async def hackertarget(domain: str) -> List[str]:
    """HackerTarget hosted hostsearch + dnslookup endpoints (100/day free)."""
    cfg = get_config()
    if not cfg.hackertarget_key:
        return []
    out: List[str] = []
    for ep, rate in (("hostsearch", 100 / 86400), ("dnslookup", 100 / 86400)):
        data = await _get(
            f"https://api.hackertarget.com/{ep}/?q={domain}&apikey={cfg.hackertarget_key}",
            {}, rate, cfg.http_timeout)
        if isinstance(data, list):
            for row in data:
                if isinstance(row, dict) and row.get("domain"):
                    out.append(row["domain"])
        elif isinstance(data, str):
            for line in data.splitlines():
                line = line.strip()
                if line and line.lower() != "error - api count exceeded":
                    out.append(line.split(",")[0].strip())
    return out


async def aggregate(domain: str) -> List[str]:
    hosts: List[str] = []
    for fn in (securitytrails, virustotal, hackertarget):
        try:
            hosts.extend(await fn(domain))
        except Exception as exc:
            log().debug("passive source %s failed: %r", fn.__name__, exc)
    return list(dict.fromkeys(h for h in hosts if h))
