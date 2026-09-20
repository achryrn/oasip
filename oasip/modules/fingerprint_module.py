"""Module 6 - Infrastructure & Technology Fingerprinting.

Reads stored scan data from Shodan/Censys/BinaryEdge, enriches each unique
IP with RDAP attribution, deep-probes each hostname (single HTTP GET + TLS
handshake), fingerprints technology with the Wappalyzer-lite signature set,
and maps detected versions to NVD CVEs.
"""
from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional

from .. import repos
from ..certutil import flags_for, parse_der
from ..db import dbsync
from ..services import binaryedge, censys, nvd, rdap, shodan, webprobe
from ..services.wappalyzer import fingerprint as wappalyzer_fp
from ..util import gather_limited, log

from .context import ScanContext

CLOUD_ORGS = {
    "amazon": "AWS", "aws": "AWS", "ec2": "AWS",
    "google": "GCP", "cloud.google": "GCP", "gcp": "GCP",
    "microsoft": "Azure", "azure": "Azure",
    "digitalocean": "DigitalOcean", "digital ocean": "DigitalOcean",
    "hetzner": "Hetzner", "ovh": "OVH", "linode": "Linode", "akamai": "Akamai",
    "cloudflare": "Cloudflare", "fastly": "Fastly", "fly.io": "Fly.io",
    "vercel": "Vercel", "netlify": "Netlify", "heroku": "Heroku",
    "choopa": "Choopa", "vultr": "Vultr",
}


def cloud_provider_for(org: str) -> Optional[str]:
    if not org:
        return None
    low = org.lower()
    for key, provider in CLOUD_ORGS.items():
        if key in low:
            return provider
    return None


def _private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return True


async def _ip_enrichment(ctx: ScanContext, ip: str) -> Dict:
    results = await gather_limited([
        shodan.host(ip), censys.host(ip), binaryedge.host(ip), rdap.ip_info(ip),
    ], 4)
    merged: Dict = {"ports": [], "banners": [], "vulns": [], "hostnames": []}
    for r in results:
        if not r:
            continue
        merged["ports"] = list(dict.fromkeys(merged.get("ports", []) + (r.get("ports") or [])))
        merged["banners"] = (merged.get("banners") or []) + (r.get("banners") or [])
        merged["vulns"] = list(dict.fromkeys(merged.get("vulns", []) + (r.get("vulns") or [])))
        for k in ("asn", "org_name", "isp", "country", "os", "hostnames"):
            v = r.get(k)
            if v and not merged.get(k):
                merged[k] = v
    merged["ports"] = sorted(set(merged["ports"]))
    # TLS config evidence from scan data banners (TLS version strings)
    tls_versions = set()
    for b in merged["banners"]:
        banner = str(b.get("banner", ""))
        for v in ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"):
            if v.lower() in banner.lower():
                tls_versions.add(v)
    merged["tls_versions"] = sorted(tls_versions)
    return merged


async def run(ctx: ScanContext) -> Dict:
    cfg = ctx.cfg
    stats: Dict = {"ips": 0, "hosts_probed": 0, "certs": 0, "cves": 0, "findings": 0}
    hosts = [h for h in (await dbsync(repos.list_hosts, ctx.scan_id)) if h.ips]
    known = {h.hostname for h in hosts}

    # late host intake: hosts mined by later stages (CT, correlate) that the
    # DNS stage never saw are resolved once and persisted here
    from ..services.resolver import resolve_a

    to_intake = [h for h in ctx.extra_hosts if h not in known and not h.startswith("*.")][: max(0, 120 - len(hosts))]

    async def intake(hostname: str) -> None:
        try:
            ips = await resolve_a(hostname)
        except Exception:
            ips = []
        await dbsync(repos.upsert_host, ctx.scan_id, hostname, source="late", ips=ips)

    if to_intake:
        log().info("fingerprint: intaking %d late-discovered hosts", len(to_intake))
        await gather_limited([intake(h) for h in to_intake], cfg.dns_concurrency)
        hosts = [h for h in (await dbsync(repos.list_hosts, ctx.scan_id)) if h.ips]

    # ---- dedupe IPs, filter RFC1918 ---------------------------------------
    ips = sorted({ip for h in hosts for ip in (h.ips or []) if not _private(ip)})
    stats["unique_ips"] = len(ips)
    ip_meta: Dict[str, Dict] = {}

    async def enrich(ip: str) -> None:
        meta = await _ip_enrichment(ctx, ip)
        ip_meta[ip] = meta
        extra = {}
        if meta.get("tls_versions"):
            extra["tls_config"] = {"versions": meta["tls_versions"]}
        await dbsync(repos.upsert_ip, ctx.scan_id, ip,
                     hostnames=[h.hostname for h in hosts if ip in (h.ips or [])],
                     asn=meta.get("asn"),
                     org_name=meta.get("org_name"),
                     isp=meta.get("isp"),
                     country=meta.get("country"),
                     os_name=meta.get("os"),
                     ports=meta.get("ports") or [],
                     banners=meta.get("banners") or [],
                     ssh_keys=[b for b in (meta.get("banners") or [])
                               if "ssh" in str(b.get("banner", "")).lower()][:5],
                     cloud_provider=cloud_provider_for(meta.get("org_name") or ""),
                     cdn=cloud_provider_for(meta.get("org_name") or "") or None,
                     vulns=meta.get("vulns") or [],
                     **extra)
        stats["ips"] += 1

    await gather_limited([enrich(ip) for ip in ips[:800]], min(cfg.concurrency, 12))

    # backfill host ASN/org/country from IP rows
    for h in hosts:
        first_ip = next((ip for ip in (h.ips or []) if not _private(ip)), None)
        meta = ip_meta.get(first_ip or "", {})
        if meta.get("asn") or meta.get("org_name"):
            await dbsync(repos.upsert_host, ctx.scan_id, h.hostname,
                         asn=meta.get("asn"), org_name=meta.get("org_name"),
                         country=meta.get("country"))

    # ---- direct probes per hostname ---------------------------------------
    probe_targets = [h for h in hosts[: max(1, min(cfg.max_hosts, 400))]]

    async def probe(host) -> None:
        probe_res = await webprobe.probe_http(host.hostname)
        techs: List[Dict] = []
        cookies = {}
        if probe_res:
            cookies = {k: v for k, v in (probe_res.get("cookies") or {}).items()}
            techs = wappalyzer_fp(probe_res.get("headers"), probe_res.get("body"), cookies)
            await dbsync(repos.upsert_host, ctx.scan_id, host.hostname,
                         http_status=probe_res.get("status"),
                         server_header=probe_res.get("server"))
            stats["hosts_probed"] += 1
        cert = await webprobe.grab_tls_cert(host.hostname)
        if cert:
            cert_info = parse_der_from_tls(cert)
            await dbsync(repos.upsert_certificate, ctx.scan_id, cert_info["identity"],
                         sha256=cert_info["sha256"],
                         domains=cert_info["sans"],
                         issuer=cert_info["issuer"],
                         subject_org=cert_info.get("org") or None,
                         not_before=cert_info["not_before"],
                         not_after=cert_info["not_after"],
                         key_algo=cert_info["key_algo"],
                         key_bits=cert_info["key_bits"],
                         sig_algo=cert_info["sig_algo"],
                         is_wildcard=cert_info["wildcard"],
                         is_self_signed=cert_info["self_signed"],
                         source="tls")
            await dbsync(repos.upsert_host, ctx.scan_id, host.hostname,
                         cert_sha256=cert_info["identity"],
                         cert_issued_date=cert_info["not_before"][:10],
                         cert_expiry=cert_info["not_after"][:10],
                         cert_issuer=cert_info["issuer"])
            stats["certs"] += 1
            flags = flags_for(cert_info)
            for flag in flags:
                if flag in ("expired", "expiring", "self-signed"):
                    sev = "high" if flag == "expired" else "medium"
                    await dbsync(repos.add_finding, ctx.scan_id, "ssl", sev,
                                 f"{flag.replace('-', ' ').title()} certificate on {host.hostname}",
                                 {"cert": cert_info["identity"],
                                  "not_after": cert_info["not_after"]},
                                 cert_info["not_after"],
                                 10.0 if flag in ("expired", "expiring") else 5.0,
                                 "host", host.hostname)
                    stats["findings"] += 1
        await dbsync(repos.upsert_host, ctx.scan_id, host.hostname, techs=techs or None)
        for t in techs:
            await dbsync(repos.upsert_technology, ctx.scan_id, host.hostname,
                         t["name"], t.get("version", ""),
                         category=t.get("category", ""),
                         confidence=t.get("confidence", 100),
                         evidence=t.get("evidence", "")[:255],
                         asset_type="host")

    await gather_limited([probe(h) for h in probe_targets], max(4, min(cfg.concurrency, 12)))

    # ---- NVD version -> CVE mapping ----------------------------------------
    techs = await dbsync(repos.list_technologies, ctx.scan_id)
    cve_lookups = [t for t in techs if t.version][:40]
    for t in cve_lookups:
        try:
            cves = await nvd.lookup(t.name, t.version)
        except Exception as exc:
            log().debug("nvd lookup failed: %r", exc)
            continue
        if not cves:
            continue
        top = cves[0]
        await dbsync(repos.upsert_technology, ctx.scan_id, t.asset_name, t.name,
                     t.version, cvss_max=top.get("cvss"),
                     cve_ids=[c["cve_id"] for c in cves])
        stats["cves"] += len(cves)
        for c in cves[:3]:
            score = c.get("cvss") or 0
            sev = c.get("severity") or "unknown"
            if score >= 9.0 or sev.lower() == "critical":
                impact, severity = 25.0, "critical"
            elif score >= 7.0 or sev.lower() == "high":
                impact, severity = 15.0, "high"
            elif score >= 4.0:
                impact, severity = 5.0, "medium"
            else:
                impact, severity = 0.0, "low"
            await dbsync(repos.add_finding, ctx.scan_id, "cve", severity,
                         f"{t.name} {t.version} on {t.asset_name} -> {c['cve_id']} (CVSS {score})",
                         {"cve": c["cve_id"], "cvss": score, "product": t.name,
                          "version": t.version, "asset": t.asset_name,
                          "description": c.get("description", "")[:200]},
                         c.get("description", "")[:300], impact, "host", t.asset_name)
            stats["findings"] += 1
    return stats


def parse_der_from_tls(cert: Dict) -> Dict:
    """Reconstruct a certutil-compatible dict from webprobe capture data."""
    return {
        "sha256": cert["sha256"],
        "identity": cert["sha256"],   # replaced below via flags-safe key
        "serial": "",
        "subject": cert.get("subject", ""),
        "issuer": cert.get("issuer", ""),
        "org": cert.get("org", ""),
        "not_before": cert.get("not_before", ""),
        "not_after": cert.get("not_after", ""),
        "key_algo": cert.get("key_algo", ""),
        "key_bits": cert.get("key_bits"),
        "sig_algo": cert.get("sig_algo", ""),
        "sans": cert.get("sans", []),
        "wildcard": cert.get("wildcard", False),
        "self_signed": cert.get("self_signed", False),
    }
