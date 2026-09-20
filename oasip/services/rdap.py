"""RDAP IP/ASN attribution - free, keyless, RFC 7480."""
from __future__ import annotations

from typing import Dict, Optional

import httpx

from ..config import get_config
from ..limits import limiter
from ..util import UA, log


async def ip_info(ip: str) -> Optional[Dict]:
    cfg = get_config()
    try:
        async with limiter("rdap", rate=4.0, burst=8):
            async with httpx.AsyncClient(timeout=cfg.http_timeout,
                                         follow_redirects=True,
                                         headers={"User-Agent": UA}) as client:
                resp = await client.get(f"https://rdap.org/ip/{ip}")
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                data = resp.json()
        asn = data.get("handle", "")
        org = ""
        country = data.get("country", "")
        for ent in data.get("entities", []) or []:
            for v in ent.get("vcardArray", [])[1:] if isinstance(ent.get("vcardArray"), list) and len(ent.get("vcardArray", [])) > 1 else []:
                if isinstance(v, list) and len(v) > 3 and v[0] == "fn":
                    org = v[3] or org
            for role in ent.get("roles", []) or []:
                if role == "registrant" and not org:
                    for v in ent.get("vcardArray", [])[1:] if isinstance(ent.get("vcardArray"), list) else []:
                        if isinstance(v, list) and len(v) > 3 and v[0] == "fn":
                            org = v[3]
        return {"asn": asn, "org_name": org, "country": country}
    except Exception as exc:
        log().debug("rdap %s failed: %r", ip, exc)
        return None
