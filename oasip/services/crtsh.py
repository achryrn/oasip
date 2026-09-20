"""Certificate Transparency client for crt.sh (no key required)."""
from __future__ import annotations

import json
from typing import Dict, List, Optional

import httpx

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from ..config import get_config
from ..limits import limiter
from ..util import UA, log, split_name_value


def _parse_json(resp):
    """Parse crt.sh JSON, tolerating a leading UTF-8 BOM."""
    text = resp.text.lstrip("\ufeff")
    try:
        return json.loads(text)
    except ValueError:
        return None

BASE = "https://crt.sh"


async def query(domain: str, expand: bool = True, limit: int = 5000) -> List[Dict]:
    """Query crt.sh for certificates matching the domain.

    expand=True uses the '%.domain' wildcard form (URL-encoded once) which
    catches both apex and subdomain certs. Falls back to the bare domain.
    """
    from urllib.parse import quote

    cfg = get_config()
    q = f"%.{domain}" if expand else domain
    url = f"{BASE}/?q={quote(q)}&output=json"
    try:
        async with limiter("crtsh", rate=0.5, burst=2):
            async with httpx.AsyncClient(timeout=max(45.0, cfg.http_timeout * 3),
                                         headers={"User-Agent": UA},
                                         follow_redirects=True) as client:
                resp = await client.get(url)
                resp.raise_for_status()
        data = _parse_json(resp)
        if data is None and expand:
            # fallback: bare-domain query
            async with limiter("crtsh", rate=0.5, burst=2):
                resp = await client.get(f"{BASE}/?q={quote(domain)}&output=json")
                resp.raise_for_status()
            data = _parse_json(resp)
    except (httpx.HTTPError, ValueError) as exc:
        log().warning("crt.sh query failed for %s: %r", domain, exc)
        return []
    if data is None:
        log().warning("crt.sh returned non-JSON for %s", q)
        return []
    data = _parse_json(resp)
    if data is None:
        log().warning("crt.sh returned non-JSON for %s", q)
        return []
    # crt.sh may return a dict {cert id: [...]} in some forms; normalize
    if isinstance(data, dict):
        rows = []
        for rows_v in data.values():
            rows.extend(rows_v if isinstance(rows_v, list) else [rows_v])
    else:
        rows = data
    return [r for r in rows if isinstance(r, dict)][:limit]


def certs_to_hosts(rows: List[Dict]) -> List[str]:
    """All SAN names (excluding wildcard prefixes) from a crt.sh result set."""
    hosts: List[str] = []
    for row in rows:
        nv = row.get("name_value", "")
        for name in split_name_value(nv):
            if name.startswith("*."):
                name = name[2:]
            if name and "." in name:
                hosts.append(name)
    return list(dict.fromkeys(hosts))


def summarize(row: Dict) -> Dict:
    return {
        "crtsh_id": row.get("id"),
        "logged_at": row.get("entry_timestamp"),
        "not_before": (row.get("not_before") or "")[:19],
        "not_after": (row.get("not_after") or "")[:19],
        "issuer": row.get("issuer_name"),
        "common_name": row.get("common_name"),
        "domains": split_name_value(row.get("name_value", "")),
        "serial": row.get("serial_number"),
    }


async def fetch_pem(cert_id: int) -> Optional[bytes]:
    """Fetch the raw certificate (DER) for a crt.sh cert id and return bytes."""
    cfg = get_config()
    try:
        async with limiter("crtsh", rate=0.5, burst=2):
            async with httpx.AsyncClient(timeout=max(45.0, cfg.http_timeout * 3),
                                         headers={"User-Agent": UA},
                                         follow_redirects=True) as client:
                resp = await client.get(f"{BASE}/", params={"d": cert_id})
                resp.raise_for_status()
        body = resp.content
        if body[:1] == b"-":
            # PEM
            pem = body.decode("utf-8", "replace")
            import re as _re
            m = _re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, _re.S)
            if not m:
                return None
            return x509.load_pem_x509_certificate(m.group(0).encode()).public_bytes(Encoding.DER)
        return body  # DER
    except Exception as exc:
        log().debug("crt.sh cert fetch %s failed: %r", cert_id, exc)
        return None
