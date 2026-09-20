"""RFC 6962 Certificate Transparency log streaming monitor.

Polls public CT logs with get-sth / get-entries, decodes RFC 6962
Merkle-tree leaves, and reports new certificates for monitored domains.
First run snapshots the log tail (no backfill) - subsequent polls only
emit certificates that actually appeared since the last check.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import httpx

from ..config import get_config
from ..limits import limiter
from ..util import log

LOGS = [
    "argon2022", "argon2023", "xenon2022", "xenon2023", "icarus",
]


def _state_file(log_name: str) -> Path:
    return get_config().data_dir / f"ct_state_{log_name}.json"


def _load_state(log_name: str) -> int:
    try:
        return int(json.loads(_state_file(log_name).read_text()).get("tree_size", 0))
    except Exception:
        return 0


def _save_state(log_name: str, tree_size: int) -> None:
    try:
        _state_file(log_name).write_text(json.dumps({"tree_size": tree_size}))
    except OSError:
        pass


def _parse_leaf(leaf_base64: str) -> Optional[bytes]:
    """Decode an RFC 6962 leaf (X509 or Precert) and return the DER cert."""
    try:
        raw = base64.b64decode(leaf_base64)
        if len(raw) < 13:
            return None
        leaf_type = raw[0]
        if leaf_type != 0:  # timestamped_entry
            return None
        entry_type = struct.unpack(">H", raw[9:11])[0]
        if entry_type == 0:   # X509Entry: 3-byte length + DER
            l = struct.unpack(">I", b"\x00" + raw[11:14])[0]
            return raw[14:14 + l]
        if entry_type == 1:   # PrecertEntry: 32-byte issuer key hash + TLSCertificate
            l = struct.unpack(">I", b"\x00" + raw[43:46])[0]
            return raw[46:46 + l]
    except Exception:
        return None
    return None


def _cert_domains(der: bytes) -> Tuple[List[str], str, str, str, str]:
    """Extract SANs and basic metadata from DER; returns (sans, issuer, nb, na, sha)."""
    from cryptography import x509
    try:
        cert = x509.load_der_x509_certificate(der)
        sans = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            sans = ext.get_values_for_type(x509.DNSName)
        except Exception:
            pass
        return (sans,
                cert.issuer.rfc4514_string(),
                cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                hashlib.sha256(der).hexdigest())
    except Exception:
        return [], "", "", "", ""


def matches(domains: List[str], monitored: str) -> Optional[str]:
    m = monitored.lower().lstrip("*.")
    for d in domains:
        d = d.lower()
        if d == m or d.endswith("." + m):
            return d
    return None


async def poll_log(client: httpx.AsyncClient, log_name: str, monitored: str,
                   on_event) -> None:
    base = f"https://ct.googleapis.com/logs/{log_name}"
    try:
        async with limiter("ctlog", rate=1.0, burst=2):
            resp = await client.get(f"{base}/ct/v1/get-sth")
            resp.raise_for_status()
            sth = resp.json()
        tree_size = int(sth.get("tree_size", 0))
        last = _load_state(log_name)
        if last == 0:
            _save_state(log_name, tree_size)
            log().info("CT log %s: snapshot at tree size %d (no backfill)", log_name, tree_size)
            return
        if tree_size <= last:
            return
        start, end = last, min(last + 200, tree_size)
        emitted = 0
        while start < tree_size:
            async with limiter("ctlog", rate=1.0, burst=2):
                resp = await client.get(f"{base}/ct/v1/get-entries",
                                        params={"start": start, "end": end - 1})
                resp.raise_for_status()
                entries = resp.json().get("entries", [])
            for entry in entries:
                der = _parse_leaf(entry.get("leaf_input", ""))
                if der:
                    sans, issuer, nb, na, sha = _cert_domains(der)
                    hit = matches(sans, monitored)
                    if hit:
                        await on_event({
                            "log": log_name,
                            "sha256": sha,
                            "domain": hit,
                            "all_domains": sans,
                            "issuer": issuer,
                            "not_before": nb,
                            "not_after": na,
                        })
                        emitted += 1
            start = end
            end = min(end + 200, tree_size)
        _save_state(log_name, tree_size)
        log().info("CT log %s: scanned %d entries, %d matches for %s",
                   log_name, tree_size - last, emitted, monitored)
    except Exception as exc:
        log().debug("CT log %s poll failed: %r", log_name, exc)


async def monitor(monitored: str, on_event, interval: Optional[int] = None) -> None:
    """Run forever, polling all configured CT logs for new certs."""
    cfg = get_config()
    interval = interval or cfg.ct_stream_interval
    log().info("CT stream monitor started for %s (interval %ss)", monitored, interval)
    async with httpx.AsyncClient(timeout=cfg.http_timeout) as client:
        while True:
            for name in LOGS:
                try:
                    await poll_log(client, name, monitored, on_event)
                except Exception as exc:
                    log().debug("ct log %s error: %r", name, exc)
            await asyncio.sleep(interval)
