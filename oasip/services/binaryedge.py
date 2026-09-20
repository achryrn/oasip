"""BinaryEdge host query - reads their stored scan data."""
from __future__ import annotations

from typing import Dict, Optional

import httpx

from ..config import get_config
from ..limits import limiter
from ..util import UA, log


async def host(ip: str) -> Optional[Dict]:
    cfg = get_config()
    if not cfg.binaryedge_key:
        return None
    try:
        async with limiter("binaryedge", rate=1.0, burst=2):
            async with httpx.AsyncClient(timeout=cfg.http_timeout, headers={
                "User-Agent": UA, "X-Key": cfg.binaryedge_key}) as client:
                resp = await client.get(f"https://api.binaryedge.io/v2/query/ip/{ip}")
                if resp.status_code == 404:
                    return None
                if resp.status_code == 401:
                    log().warning("BinaryEdge: invalid API key")
                    return None
                resp.raise_for_status()
        data = resp.json()
        events = (data.get("events") or [])[:50]
        ports, banners = [], []
        for ev in events:
            port = ev.get("port")
            ports.append(port)
            res = ev.get("result", {})
            if isinstance(res, dict) and res.get("data"):
                banners.append({
                    "port": port,
                    "protocol": ev.get("protocol"),
                    "banner": str(res.get("data"))[:300],
                })
        return {
            "ip": ip,
            "ports": sorted(set(p for p in ports if p)),
            "banners": banners,
            "vulns": [],
            "hostnames": [],
        }
    except Exception as exc:
        log().debug("BinaryEdge %s failed: %r", ip, exc)
        return None
