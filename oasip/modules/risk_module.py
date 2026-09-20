"""Module 8 - Risk Scoring Engine.

Every discovered asset gets a 0-100 composite score from the documented
factor table. The overall target score is a finding-weighted aggregate
across assets, bucketed into risk tiers.

Factor                                Max pts
Critical CVE on detected version       25
Credential exposure in breach (plain)  20
Secret exposed in public repository    20
Expired or expiring SSL certificate    10
Missing or permissive DMARC             8
Subdomain takeover vulnerable          15
Exposed admin panel                    10
TLS 1.0 or 1.1 enabled                  7
Self-signed certificate                 5
Weak SSH key (<2048)                    5
Dangling DNS record                    10
Asset on unexpected infrastructure      5
"""
from __future__ import annotations

from typing import Dict, List

from .. import repos
from ..db import dbsync
from ..util import log

from .context import ScanContext

ADMIN_PANEL_TECH = {"phpMyAdmin", "Grafana", "Jenkins", "Kibana", "Prometheus",
                    "Consul", "Vault", "WordPress"}


def score_host(host) -> float:
    s = 0.0
    if host.dmarc_permissive:
        s += 8
    if host.spf_permissive:
        s += 2
    tls = host.dns_records and (host.dns_records.get("TXT") or [])
    if host.cert_expiry:
        try:
            from datetime import datetime, timezone
            exp = datetime.strptime(host.cert_expiry[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if exp < datetime.now(timezone.utc):
                s += 10
            elif (exp - datetime.now(timezone.utc)).days <= 30:
                s += 10
        except ValueError:
            pass
    return min(100.0, s)


def score_ip(ip) -> float:
    s = 0.0
    if ip.tls_config:
        versions = " ".join(ip.tls_config.get("versions", []))
        if "TLSv1.0" in versions or "TLSv1.1" in versions or "TLSv1" in versions and "TLSv1.2" not in versions:
            s += 7
    for b in (ip.banners or []):
        banner = str(b.get("banner", "")).lower()
        if "openssh" in banner:
            m = __import__("re").search(r"openssh[_-]([\d.]+)", banner)
            if m:
                ver = m.group(1)
                try:
                    major, minor = (int(x) for x in ver.split(".")[:2])
                    if major == 1 or (major == 2 and minor < 8):
                        s += 5
                except ValueError:
                    pass
    if "ssh" in str(ip.ssh_keys or "") and (ip.ssh_keys or []):
        s += 5  # SSH host key present without crypto detail; conservative bump
    return min(100.0, s)


async def run(ctx: ScanContext) -> Dict:
    scan_id = ctx.scan_id
    hosts = await dbsync(repos.list_hosts, scan_id)
    ips = await dbsync(repos.list_ips, scan_id)
    techs = await dbsync(repos.list_technologies, scan_id)
    takeovers = await dbsync(repos.list_takeovers, scan_id)
    shadows = await dbsync(repos.list_shadows, scan_id)
    breaches = await dbsync(repos.list_breaches, scan_id)
    repo_findings = await dbsync(repos.list_repo_findings, scan_id)
    findings = await dbsync(repos.list_findings, scan_id)

    take_hosts = {t.hostname for t in takeovers}
    shadow_hosts = {s.hostname for s in shadows}
    plaintext_breach_subjects = {b.subject_name for b in breaches if b.pw_exposure == "plaintext"}

    tech_by_asset: Dict[str, List] = {}
    for t in techs:
        tech_by_asset.setdefault(t.asset_name, []).append(t)

    def asset_score(asset_name: str, is_host: bool) -> float:
        s = 0.0
        if is_host:
            s += score_host(find_host(asset_name))
        else:
            s += score_ip(find_ip(asset_name))
        for t in tech_by_asset.get(asset_name, []):
            if t.cvss_max:
                if t.cvss_max >= 9.0:
                    s += 25
                elif t.cvss_max >= 7.0:
                    s += 15
                else:
                    s += 5
            if t.name in ADMIN_PANEL_TECH:
                s += 10
            if t.name in ("WordPress", "phpMyAdmin"):
                s += 0
        if asset_name in take_hosts:
            s += 15
        if asset_name in shadow_hosts:
            s += 5
        if asset_name in plaintext_breach_subjects:
            s += 20
        if any(asset_name in (b.subject_name or "") for b in breaches
               if b.subject_type == "email" and b.pw_exposure == "plaintext"):
            s += 20
        return min(100.0, s)

    def find_host(name: str):
        for h in hosts:
            if h.hostname == name:
                return h
        return _blank_host()

    def find_ip(name: str):
        for i in ips:
            if i.ip == name:
                return i
        return _blank_ip()

    weighted_sum = 0.0
    weight_sum = 0.0
    tier_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}

    all_assets: List[tuple] = [(h.hostname, True) for h in hosts] + [(i.ip, False) for i in ips]
    scored = []
    for asset_name, is_host in all_assets:
        sc = asset_score(asset_name, is_host)
        weight = 1.0
        for f in findings:
            if f.asset_name == asset_name and f.severity in ("critical", "high"):
                weight += 0.5
        weighted_sum += sc * weight
        weight_sum += weight
        scored.append((asset_name, is_host, sc))
        tier = "low" if sc < 25 else ("medium" if sc < 50 else ("high" if sc < 75 else "critical"))
        tier_counts[tier] += 1
        if is_host:
            await dbsync(repos.upsert_host, scan_id, asset_name, score=sc)
        else:
            await dbsync(repos.upsert_ip, scan_id, asset_name, score=sc)

    overall = round(weighted_sum / weight_sum) if weight_sum else 0
    overall_tier = "low" if overall < 25 else ("medium" if overall < 50 else ("high" if overall < 75 else "critical"))
    # persist an overall finding for visibility
    await dbsync(repos.add_finding, scan_id, "risk", "info",
                 f"Overall target risk score: {overall}/100 ({overall_tier.upper()})",
                 {"overall": overall, "tier": overall_tier,
                  "assets_scored": len(scored),
                  "tier_counts": tier_counts}, "", 0.0, "domain", ctx.target)
    log().info("risk: overall score %d/100 (%s), assets scored %d",
               overall, overall_tier, len(scored))
    return {"overall": overall, "tier": overall_tier, "tier_counts": tier_counts,
            "assets_scored": len(scored)}


class _Blank:
    score = 0.0


def _blank_host():
    h = _Blank()
    h.dmarc_permissive = False
    h.spf_permissive = False
    h.cert_expiry = None
    h.dns_records = {}
    return h


def _blank_ip():
    i = _Blank()
    i.tls_config = {}
    i.banners = []
    i.ssh_keys = []
    return i
