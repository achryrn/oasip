"""Censys v2 hosts API - reads Censys's stored internet scan data."""
from __future__ import annotations

from typing import Dict, Optional

import httpx

from ..config import get_config
from ..limits import limiter
from ..util import UA, log


async def host(ip: str) -> Optional[Dict]:
    cfg = get_config()
    if not cfg.censys_id or not cfg.censys_secret:
        return None
    try:
        async with limiter("censys", rate=250 / 2592000, burst=2):
            async with httpx.AsyncClient(timeout=cfg.http_timeout, headers={"User-Agent": UA}) as client:
                resp = await client.get(
                    f"https://search.censys.io/api/v2/hosts/{ip}",
                    auth=(cfg.censys_id, cfg.censys_secret))
                if resp.status_code == 404:
                    return None
                if resp.status_code in (401, 403):
                    log().warning("Censys: auth failed")
                    return None
                resp.raise_for_status()
        result = resp.json().get("result", {})
        services = []
        ports = []
        for svc in result.get("services", []):
            ports.append(svc.get("port"))
            services.append({
                "port": svc.get("port"),
                "service_name": svc.get("service_name"),
                "transport_protocol": svc.get("transport_protocol"),
                "software": (svc.get("software") or [{}])[0].get("product"),
                "version": (svc.get("software") or [{}])[0].get("version"),
                "banner": (svc.get("http") or {}).get("response", {}).get("body", "")[:300]
                          or str(svc.get("banner", ""))[:300],
            })
        location = result.get("location", {})
        return {
            "ip": ip,
            "asn": result.get("autonomous_system", {}).get("asn"),
            "org": result.get("autonomous_system", {}).get("name"),
            "isp": None,
            "country": location.get("country"),
            "os": result.get("operating_system", {}).get("product_name"),
            "ports": sorted(set(ports)),
            "banners": services,
            "vulns": [],
            "hostnames": [],
        }
    except Exception as exc:
        log().debug("Censys %s failed: %r", ip, exc)
        return None
