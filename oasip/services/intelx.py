"""IntelligenceX (IntelX) search client - paste sites, breach dumps, darkweb mirrors."""
from __future__ import annotations

import asyncio
from typing import Dict, List, Optional

import httpx

from ..config import get_config
from ..limits import limiter
from ..util import UA, log

BASE = "https://2.intelx.io"


def _headers() -> Dict[str, str]:
    cfg = get_config()
    return {"x-key": cfg.intelx_key, "User-Agent": UA}


async def search(term: str, maxresults: int = 25) -> List[Dict]:
    """Search and pull result metadata. IntelX free tier caps result counts."""
    cfg = get_config()
    if not cfg.intelx_key:
        return []
    try:
        async with limiter("intelx", rate=0.2, burst=1):
            async with httpx.AsyncClient(timeout=cfg.http_timeout, headers=_headers()) as client:
                resp = await client.post(f"{BASE}/search", json={
                    "term": term, "maxresults": maxresults, "media": 0,
                    "sort": 2, "target": 0, "terminate": []})
                if resp.status_code == 403:
                    log().warning("IntelX: free tier quota or invalid key")
                    return []
                resp.raise_for_status()
                body = resp.json()
                search_id = body.get("id") or body.get("search_id")
                if not search_id:
                    return []
                total = body.get("totalresults", 0)
                await asyncio.sleep(1)  # allow the search to settle server-side
                r2 = await client.get(f"{BASE}/search/result",
                                      params={"id": search_id, "limit": maxresults})
                if r2.status_code != 200:
                    return []
                result_body = r2.json()
        records = []
        for rec in result_body.get("records", []) or []:
            records.append({
                "name": rec.get("name", ""),
                "media": rec.get("media", ""),
                "date": rec.get("date", ""),
                "size": rec.get("size", 0),
                "flags": rec.get("flags", 0),
                "bucket": rec.get("bucket", ""),
            })
        return [{"totalresults": total, "records": records}]
    except Exception as exc:
        log().debug("IntelX search %r failed: %r", term, exc)
        return []
