"""Shodan host lookup - reads Shodan's existing scan data (1 credit/query)."""
from __future__ import annotations

from typing import Dict, List, Optional

import httpx

from ..config import get_config
from ..limits import limiter
from ..util import UA, log


async def host(ip: str) -> Optional[Dict]:
    cfg = get_config()
    if not cfg.shodan_key:
        return None
    try:
        async with limiter("shodan", rate=100 / 2592000, burst=2):
            async with httpx.AsyncClient(timeout=cfg.http_timeout, headers={"User-Agent": UA}) as client:
                resp = await client.get(
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": cfg.shodan_key})
                if resp.status_code == 404:
                    return None
                if resp.status_code == 401:
                    log().warning("Shodan: invalid API key")
                    return None
                resp.raise_for_status()
        data = resp.json()
        ports, banners = [], []
        for item in data.get("data", []):
            ports.append(item.get("port"))
            banners.append({
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "version": item.get("version"),
                "banner": item.get("data", "")[:300],
                "ssl": (item.get("ssl") or {}).get("cert") and {
                    "subject": (item.get("ssl") or {}).get("cert", {}).get("subject"),
                    "issuer": (item.get("ssl") or {}).get("cert", {}).get("issuer"),
                },
            })
        out = {
            "ip": ip,
            "asn": data.get("asn"),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "country": data.get("country_name"),
            "os": data.get("os"),
            "ports": sorted(set(ports)),
            "banners": banners,
            "vulns": data.get("vulns", []),
            "hostnames": data.get("hostnames", []),
        }
        https = next((b for b in banners if b.get("port") == 443), None)
        if https and https.get("ssl"):
            tls = {
                "cert_subject": https["ssl"].get("subject"),
                "cert_issuer": https["ssl"].get("issuer"),
            }
            out["tls_config"] = tls
        return out
    except Exception as exc:
        log().debug("Shodan %s failed: %r", ip, exc)
        return None
