"""Module 7 - Asset Correlation Engine.

Builds IP/host/cert/ASN relationships, flags shadow IT and dangling DNS, and
detects subdomain takeover candidates using provider error-page fingerprints.
"""
from __future__ import annotations

from typing import Dict, List

from .. import repos
from ..db import dbsync
from ..services import webprobe
from ..services.resolver import resolve_a
from ..util import gather_limited, log

from .context import ScanContext

TAKEOVER_FINGERPRINTS = [
    ("GitHub Pages", ["There isn't a GitHub Pages site here", "For root URLs (like https://example.com) you must provide"]),
    ("Heroku", ["No such app", "herokucdn.com/error-pages/no-such-app.html"]),
    ("Netlify", ["Not found - Request ID", "Looks like you've found something that doesn't exist", "Netlify"]),
    ("Vercel", ["The requested page could not be found", "VERCEL", "Deployed to Vercel"]),
    ("AWS S3", ["NoSuchBucket", "The specified bucket does not exist"]),
    ("Azure Blob", ["The specified resource does not exist", "404 Not Found", "AccountRequiresHttps"]),
    ("Shopify", ["Sorry, this shop is currently unavailable", "This shop is currently unavailable"]),
    ("Zendesk", ["Help Center Closed", "Zendesk"]),
    ("Fastly", ["Fastly error: unknown domain", "Fastly error: no domain"]),
    ("Tumblr", ["There's nothing here, yet."]),
    ("Surge.sh", ["project not found"]),
    ("Bitbucket", ["Repository not found"]),
    ("Pantheon", ["404 error unknown site"]),
    ("ReadMe.io", ["Project doesnt exist... yet"]),
    ("Ghost", ["The thing you were looking for is no longer here"]),
    ("Cargo Collective", ["502 Bad Gateway"]),
    ("WordPress.com", ["Do you want to register", "domain is not a registered"]),
    ("GetResponse", ["With GetResponse Landing Pages"]),
    ("Webflow", ["The page you are looking for doesn't exist"]),
    ("Aerobatic", ["There is no such page"]),
    ("Statuspage", ["The page you are looking for does not exist"]),
    ("Launchrock", ["It looks like you may have taken a wrong turn"]),
    ("Strikingly", ["But the site you were looking for no longer exists"]),
    ("SmartJobBoard", ["This job board website is either expired"]),
    ("HubSpot", ["The page you're looking for doesn't exist"]),
]

CONSUMER_HOSTERS = ("herokuapp.com", "vercel.app", "netlify.app", "github.io",
                    "surge.sh", "web.app", "firebaseapp.com", "pages.dev",
                    "azurewebsites.net", "cloudfront.net", "s3.amazonaws.com",
                    "amazonaws.com", "onrender.com", "fly.dev", "glitch.me",
                    "railway.app", "workers.dev", "pantheonsite.io")


async def run(ctx: ScanContext) -> Dict:
    scan_id = ctx.scan_id
    stats: Dict = {"vhosts": 0, "asn_groups": 0, "shadow": 0, "takeovers": 0}
    hosts = [h for h in (await dbsync(repos.list_hosts, scan_id))]
    ips = await dbsync(repos.list_ips, scan_id)
    certs = await dbsync(repos.list_certs, scan_id)

    # IP -> hostnames, ASN groupings
    ip_to_hosts: Dict[str, List[str]] = {}
    asn_groups: Dict[str, List[str]] = {}
    for h in hosts:
        for ip in (h.ips or []):
            ip_to_hosts.setdefault(ip, []).append(h.hostname)
        if h.asn:
            asn_groups.setdefault(h.asn, []).append(h.hostname)
    stats["vhosts"] = sum(len(v) for v in ip_to_hosts.values() if len(v) > 1)
    stats["asn_groups"] = len(asn_groups)

    # certificate reuse grouping
    cert_groups: Dict[str, List[str]] = {}
    for c in certs:
        if c.reuse_count and c.domains:
            cert_groups[c.sha256] = c.domains[:10]

    # ---- shadow IT detection ----------------------------------------------
    target_tokens = [t for t in (ctx.org_name or "").lower().split() if len(t) > 3]
    ip_org: Dict[str, str] = {i.ip: (i.org_name or "") for i in ips}
    for h in hosts:
        if not h.ips:
            continue
        cloud_hosting = False
        for ip in h.ips:
            org = ip_org.get(ip, "")
            low = org.lower()
            if any(k in low for k in ("amazon", "aws", "google cloud", "microsoft azure",
                                      "digitalocean", "hetzner", "ovh", "cloudflare",
                                      "fastly", "vercel", "netlify", "heroku", "linode")):
                cloud_hosting = True
        if cloud_hosting and target_tokens:
            orgs = set(ip_org.get(ip, "") for ip in h.ips if ip in ip_org)
            if not any(any(t in o.lower() for t in target_tokens) for o in orgs if o):
                await dbsync(repos.add_shadow, scan_id, h.hostname,
                             "hostname on consumer cloud provider outside known corporate ranges",
                             {"ips": h.ips, "orgs": sorted(orgs)})
                await dbsync(repos.add_finding, ctx.scan_id, "shadow", "medium",
                             f"Shadow IT candidate: {h.hostname} hosted on unmanaged cloud infrastructure",
                             {"ips": h.ips, "orgs": sorted(orgs)}, "", 5.0, "host", h.hostname)
                stats["shadow"] += 1
        # dangling CNAME to a hosting provider
        if h.cname_target and any(h.cname_target.endswith(d) for d in CONSUMER_HOSTERS):
            await dbsync(repos.add_shadow, scan_id, h.hostname,
                         f"CNAME to third-party host {h.cname_target}",
                         {"cname": h.cname_target})
            stats["shadow"] += 1

    # ---- subdomain takeover detection --------------------------------------
    candidates = [h for h in hosts if h.cname_target]
    seen = set()

    async def check(h) -> None:
        hostname = h.hostname
        cname = h.cname_target or ""
        ips = await resolve_a(hostname)
        if not ips and cname:
            # dangling: NXDOMAIN with a live CNAME = strong takeover signal
            svc = next((s for s, _ in TAKEOVER_FINGERPRINTS
                        if s.lower().replace(" ", "") in cname.lower()), "Unknown")
            await dbsync(repos.upsert_takeover, scan_id, hostname,
                         cname_target=cname, service=svc or "Unknown",
                         fingerprint="NXDOMAIN + CNAME", status="potential")
            await dbsync(repos.add_finding, ctx.scan_id, "takeover", "high",
                         f"Takeover candidate: {hostname} (CNAME {cname}, no resolution)",
                         {"cname": cname}, "", 15.0, "host", hostname)
            stats["takeovers"] += 1
            return
        probe = await webprobe.probe_http(hostname)
        if not probe:
            return
        body = (probe.get("body") or "")[:50_000]
        for svc, needles in TAKEOVER_FINGERPRINTS:
            if all(n.lower() in body.lower() for n in needles[:2]):
                await dbsync(repos.upsert_takeover, scan_id, hostname,
                             cname_target=cname, service=svc,
                             fingerprint=";".join(needles[:2]), status="vulnerable")
                await dbsync(repos.add_finding, ctx.scan_id, "takeover", "critical",
                             f"Subdomain takeover: {hostname} -> {svc}",
                             {"cname": cname, "service": svc}, body[:200],
                             15.0, "host", hostname)
                stats["takeovers"] += 1
                break

    await gather_limited([check(h) for h in candidates[:120]], 6)
    return stats
