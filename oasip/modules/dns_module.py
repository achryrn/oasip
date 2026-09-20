"""Module 1 - DNS & Subdomain Enumeration.

Aggregates crt.sh SANs, passive DNS sources, and wordlist brute-force into a
unified host list; resolves full DNS record sets; checks SPF/DMARC/DKIM
policy posture and attempts a single AXFR query.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Set

from .. import repos
from ..db import dbsync
from ..services import crtsh, passivedns
from ..services.resolver import (detect_wildcard, dns_policy_for, resolve_a,
                                 resolve_all, try_axfr)
from ..util import gather_limited, is_subdomain, log

# Keep the module importable without the pipeline's context type
from .context import ScanContext  # noqa: E402


def _load_wordlist(ctx: ScanContext) -> List[str]:
    words: List[str] = []
    base = ctx.cfg.stopwords_file
    paths = [base]
    if str(base) != "wordlists/default_subdomains.txt":
        paths.insert(0, base)
    for p in paths:
        try:
            words.extend(
                line.strip().lower() for line in p.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#") and "," not in line and " " not in line)
        except OSError:
            continue
    return list(dict.fromkeys(words))


async def run(ctx: ScanContext) -> Dict:
    cfg = ctx.cfg
    target = ctx.target
    stats: Dict = {}
    pool: Dict[str, str] = {target: "root"}

    # 1. wildcard DNS detection -------------------------------------------
    try:
        wildcard = await detect_wildcard(target)
    except Exception:
        wildcard = False
    stats["wildcard"] = wildcard

    # 2. crt.sh SAN mining -------------------------------------------------
    rows = await crtsh.query(target)
    for h in crtsh.certs_to_hosts(rows):
        if is_subdomain(h, target):
            pool.setdefault(h, "ct")
    stats["ct_hosts"] = sum(1 for v in pool.values() if v == "ct")

    # 2b. one level of recursive CT expansion on interesting subdomains
    sub_candidates = [h for h in list(pool) if h != target][:8]
    for sub in sub_candidates:
        sub_rows = await crtsh.query(sub, expand=True, limit=300)
        for h in crtsh.certs_to_hosts(sub_rows):
            if is_subdomain(h, target):
                pool.setdefault(h, "ct")

    # 3. passive DNS sources ----------------------------------------------
    try:
        for h in await passivedns.aggregate(target):
            if is_subdomain(h, target):
                pool.setdefault(h, "passivedns")
    except Exception as exc:
        log().debug("passive dns failed: %r", exc)
    stats["passive_hosts"] = sum(1 for v in pool.values() if v == "passivedns")

    # 4. wordlist brute force (semi-passive DNS queries) -------------------
    words = _load_wordlist(ctx)
    candidates = [f"{w}.{target}" for w in words if w]
    stats["wordlist_size"] = len(candidates)
    brute_found: Set[str] = set()
    resolved = await gather_limited(
        [resolve_a(h) for h in candidates if len(pool) < cfg.max_hosts],
        cfg.dns_concurrency)
    for h, ips in zip(candidates, resolved):
        if ips:
            brute_found.add(h)
    for h in brute_found:
        pool.setdefault(h, "brute")
    stats["brute_found"] = len(brute_found)
    stats["total_hosts"] = len(pool)

    # 5. resolve each unique host --------------------------------------------
    hosts_all = list(pool)
    if len(hosts_all) > cfg.max_hosts:
        hosts_all = hosts_all[:cfg.max_hosts]
    cname_seen: Dict[str, str] = {}
    resolved_done = 0
    async def process(hostname: str) -> None:
        nonlocal resolved_done
        recs = await resolve_all(hostname)
        ips = list(dict.fromkeys(recs.get("A", []) + recs.get("AAAA", [])))
        if not ips and not recs.get("CNAME"):
            return
        cname = (recs.get("CNAME") or [None])[0] or None
        if cname:
            cname_seen[hostname] = cname
        root_fields = {}
        if hostname == target:
            pol = await dns_policy_for(target)
            spf, dmarc = pol["spf"], pol["dmarc"]
            dkim = pol["dkim_selectors"]
            root_fields.update({
                "spf_policy": spf["policy"], "spf_ip_ranges": spf["ip_ranges"],
                "spf_third_party": spf["third_party"], "spf_permissive": spf["permissive"],
                "dmarc_policy": dmarc["policy"], "dmarc_permissive": dmarc["permissive"],
                "dkim_present": pol["dkim_present"],
                "dns_records": {k: v for k, v in pol["records"].items()},
            })
            await dbsync(_policy_findings, ctx, spf, dmarc, dkim)
        fields = dict(root_fields) if hostname == target else {"dns_records": recs}
        await dbsync(repos.upsert_host, ctx.scan_id, hostname,
                     is_root=hostname == target, source=pool[hostname],
                     ips=ips, cname_target=cname,
                     wildcard_dns=wildcard if hostname == target else None,
                     **fields)
        resolved_done += 1

    await gather_limited([process(h) for h in hosts_all], cfg.concurrency)
    stats["resolved"] = resolved_done

    # 6. AXFR attempt --------------------------------------------------------
    try:
        zone = await try_axfr(target)
        if zone:
            await dbsync(repos.add_finding, ctx.scan_id, "config", "high",
                         f"Zone transfer (AXFR) is open on {target}",
                         {"records": len(zone)}, "\n".join(zone[:20]),
                         10.0, "domain", target)
        stats["axfr"] = bool(zone)
    except Exception as exc:
        log().debug("axfr failed: %r", exc)
        stats["axfr"] = False

    # register newly discovered hostnames in the context pool
    ctx.add_hosts(list(pool), source="dns")
    return stats


def _policy_findings(ctx: ScanContext, spf: Dict, dmarc: Dict, dkim: List[str]) -> None:
    if spf.get("permissive"):
        repos.add_finding(ctx.scan_id, "config", "medium",
                          f"Permissive SPF policy ({spf.get('policy')}) on {ctx.target} allows sender spoofing",
                          {"policy": spf.get("policy"), "raw": spf.get("raw", "")[:500]},
                          spf.get("raw", "")[:500], 0.0, "domain", ctx.target)
    if dmarc.get("policy") in ("missing", "none"):
        repos.add_finding(ctx.scan_id, "config", "medium",
                          f"DMARC {dmarc.get('policy')} on {ctx.target} - email spoofing not fully mitigated",
                          {"policy": dmarc.get("policy"), "raw": dmarc.get("raw", "")[:300]},
                          dmarc.get("raw", "")[:300], 0.0, "domain", ctx.target)
    if not dkim:
        repos.add_finding(ctx.scan_id, "config", "info",
                          f"No DKIM selectors found for {ctx.target}",
                          {}, "", 0.0, "domain", ctx.target)
    if not spf.get("present"):
        repos.add_finding(ctx.scan_id, "config", "low",
                          f"No SPF record on {ctx.target}", {}, "", 0.0, "domain", ctx.target)
