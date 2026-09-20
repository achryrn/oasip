"""Direct, low-volume probing of discovered hosts: HTTP headers/body,
TLS leaf certificate capture, and shallow TCP banner reads. No scanning -
a handful of handshake/GET requests per asset, rate limited.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import socket
from typing import Dict, List, Optional

import httpx

from ..config import get_config
from ..limits import limiter
from ..util import UA, log, sample

PORT_BANNER_TIMEOUT = 3.0


def _hdr_map(headers) -> Dict[str, str]:
    out = {}
    for k, v in headers.items():
        out[str(k).lower()] = str(v)
    return out


async def probe_http(host: str) -> Optional[Dict]:
    """Fetch http(s)://host/ and return status, headers, body sample, title."""
    cfg = get_config()
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            async with limiter("webprobe", rate=1.0, burst=2):
                async with httpx.AsyncClient(timeout=cfg.probe_timeout,
                                             headers={"User-Agent": UA, "Accept": "text/html,*/*"},
                                             follow_redirects=True,
                                             verify=cfg.probe_timeout > 0) as client:
                    resp = await client.get(url)
            body = resp.text[:300_000]
            title = ""
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            if m:
                title = " ".join(m.group(1).split())[:200]
            return {
                "url": str(resp.url),
                "status": resp.status_code,
                "headers": _hdr_map(resp.headers),
                "body": body,
                "title": title,
                "final_host": resp.url.host,
                "server": resp.headers.get("server", ""),
                "cookies": {k: v for k, v in resp.cookies.items()} or None,
            }
        except (httpx.HTTPError, OSError) as exc:
            log().debug("probe %s (%s) failed: %r", host, scheme, exc)
            continue
    return None


async def grab_tls_cert(host: str, port: int = 443, server_hostname: Optional[str] = None) -> Optional[Dict]:
    """TLS handshake and leaf-certificate capture (no data sent beyond handshake)."""
    import ssl

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sn = server_hostname or host
    try:
        async with limiter("tls_probe", rate=1.0, burst=2):
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context, server_hostname=sn),
                timeout=cfg_timeout())
            cert_der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        if not cert_der:
            return None
        cert = x509.load_der_x509_certificate(cert_der)
        sha256 = hashlib.sha256(cert_der).hexdigest()
        try:
            key_bits = cert.public_key().key_size
        except Exception:
            key_bits = None
        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        sans: List[str] = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            for name in ext.get_values_for_type(x509.DNSName):
                sans.append(name)
        except Exception:
            pass
        self_signed = issuer == subject
        wildcard = any(s.startswith("*.") for s in sans)
        try:
            sig_algo = cert.signature_algorithm_oid._name
        except Exception:
            sig_algo = str(cert.signature_algorithm_oid)
        return {
            "sha256": sha256,
            "subject": subject,
            "issuer": issuer,
            "org": _org_from_subject(cert),
            "not_before": cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "not_after": cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "key_algo": cert.public_key().__class__.__name__,
            "key_bits": key_bits,
            "sig_algo": sig_algo,
            "sans": sans,
            "wildcard": wildcard,
            "self_signed": self_signed,
        }
    except (asyncio.TimeoutError, OSError, Exception) as exc:
        if not isinstance(exc, (asyncio.TimeoutError, OSError, ssl.SSLError, socket.gaierror)):
            log().debug("tls grab %s failed: %r", host, exc)
        return None


def _org_from_subject(cert) -> str:
    from cryptography import x509
    try:
        for attr in cert.subject:
            if attr.oid == x509.NameOID.ORGANIZATION_NAME:
                return attr.value
    except Exception:
        pass
    return ""


def cfg_timeout() -> float:
    return get_config().probe_timeout


BANNER_PORTS = [22, 25, 80, 443, 8080, 8443, 3306, 5432, 6379, 9200]


async def grab_banners(host: str, ports: Optional[List[int]] = None) -> List[Dict]:
    """Connect and read the server greeting (nothing else) on common ports."""
    out: List[Dict] = []
    for port in (ports or BANNER_PORTS):
        try:
            async with limiter("banner", rate=4.0, burst=8):
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=PORT_BANNER_TIMEOUT)
                data = b""
                try:
                    data = await asyncio.wait_for(reader.read(256), timeout=1.5)
                except (asyncio.TimeoutError, Exception):
                    pass
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            if data:
                out.append({"port": port, "banner": sample(data.decode("utf-8", "replace"), 160)})
        except (asyncio.TimeoutError, OSError, Exception):
            pass
    return out
