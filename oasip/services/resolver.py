"""Async DNS resolution with a rotating resolver pool.

Covers A/AAAA/CNAME/MX/TXT/NS/SOA/PTR extraction, SPF/DMARC/DKIM parsing,
wildcard-DNS detection and a single-shot AXFR attempt (a plain DNS query).
"""
from __future__ import annotations

import asyncio
import hashlib
import random
import re
from typing import Dict, List, Optional, Tuple

import dns.asyncquery
import dns.asyncresolver
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rdatatype
import dns.resolver

from ..config import get_config
from ..limits import limiter
from ..util import log, random_label

_dns_limiter = None


def _resolver() -> dns.asyncresolver.Resolver:
    cfg = get_config()
    r = dns.asyncresolver.Resolver()
    r.nameservers = cfg.dns_servers
    r.lifetime = cfg.dns_timeout
    r.timeout = cfg.dns_timeout / 2
    r.rotate = True
    return r


async def resolve_a(host: str) -> List[str]:
    """A record lookup with per-server retry and a global DNS rate guard."""
    cfg = get_config()
    r = _resolver()
    last: Optional[Exception] = None
    for server in list(cfg.dns_servers) + [cfg.dns_servers[0]]:
        try:
            r.nameservers = [server]
            async with limiter("dns", rate=80, burst=120):
                ans = await r.resolve(host, "A", raise_on_no_answer=False)
            return sorted({a.address for a in ans})
        except dns.resolver.NXDOMAIN:
            return []
        except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer,
                dns.exception.DNSException, OSError) as exc:
            last = exc
            continue
    log().debug("resolve_a(%s) failed: %r", host, last)
    return []


async def resolve_all(host: str) -> Dict:
    """Resolve every interesting record type for a host into a dict."""
    r = _resolver()
    out: Dict = {}
    types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR"]
    for rdtype in types:
        try:
            ans = await r.resolve(host, rdtype, raise_on_no_answer=False, lifetime=4)
            vals = []
            for rr in ans:
                if rdtype in ("MX",):
                    exchange = rr.exchange.to_text().rstrip(".")
                    if exchange and exchange != ".":
                        vals.append(f"{exchange} prio={rr.preference}")
                elif rdtype == "SOA":
                    vals.append(rr.to_text())
                elif rdtype == "TXT":
                    vals.append(b"".join(s.encode() if isinstance(s, str) else s for s in rr.strings).decode("utf-8", "replace"))
                elif rdtype == "PTR":
                    vals.append(rr.target.to_text().rstrip("."))
                else:
                    vals.append(rr.to_text().rstrip("."))
            out[rdtype] = sorted(set(vals))
        except dns.resolver.NXDOMAIN:
            out[rdtype] = []
        except dns.resolver.NoAnswer:
            out[rdtype] = []
        except (dns.exception.DNSException, OSError):
            out[rdtype] = []
    return out


async def detect_wildcard(domain: str) -> bool:
    """Resolve a random label; if it answers, the zone uses a wildcard record."""
    probe = f"{random_label(12)}.{domain}"
    ips = await resolve_a(probe)
    if ips:
        log().info("wildcard DNS detected for %s (probe %s -> %s)", domain, probe, ips)
    return bool(ips)


async def nslookup(host: str) -> List[str]:
    """Name server hostnames for a domain."""
    r = _resolver()
    try:
        ans = await r.resolve(host, "NS", raise_on_no_answer=False, lifetime=4)
        return sorted({a.to_text().rstrip(".") for a in ans})
    except (dns.exception.DNSException, OSError):
        return []


async def try_axfr(domain: str) -> Optional[List[str]]:
    """One-shot AXFR attempt against the first usable NS. A standard DNS
    query - non-destructive - returns transferred records if the admin left
    the zone transfer open (itself a finding)."""
    ns_hosts = await nslookup(domain)
    if not ns_hosts:
        return None
    for ns in ns_hosts[:2]:
        ips = await resolve_a(ns)
        if not ips:
            continue
        q = dns.message.make_query(domain, dns.rdatatype.AXFR)
        try:
            async with limiter("dns", rate=10, burst=20):
                resp = await dns.asyncquery.axfr(ips[0], domain, timeout=8, lifetime=8)
            zonerecs = []
            for msg in resp:
                for rr in msg.answer:
                    zonerecs.append(rr.to_text())
            if zonerecs:
                log().warning("AXFR open on %s via %s (%d records)", domain, ns, len(zonerecs))
                return zonerecs
        except (dns.exception.FormError, dns.exception.Timeout, OSError):
            continue
    return None


# --- SPF / DMARC / DKIM ---------------------------------------------------

_SPF_RE = re.compile(r"(ip4|ip6):([0-9a-fA-F.:/]+)")
_INCLUDE_RE = re.compile(r"include:([A-Za-z0-9._-]+)")
_ALL_RE = re.compile(r"\s([+~?-]all)\s*")


def parse_spf(txt_records: List[str]) -> Dict:
    """Parse SPF records: policy (all mechanism), allowed ranges, third-party
    senders via include/redirect, and permissiveness (+all => worst)."""
    spf_txt = ""
    for t in txt_records:
        t = t.strip()
        if t.lower().startswith("v=spf1"):
            spf_txt = t
            break
    if not spf_txt:
        return {"present": False, "policy": "none", "ip_ranges": [],
                "third_party": [], "permissive": True,
                "raw": ""}
    ip_ranges = [f"{m.group(1)}:{m.group(2)}" for m in _SPF_RE.finditer(spf_txt)]
    third_party = list(dict.fromkeys(m.group(1) for m in _INCLUDE_RE.finditer(spf_txt)))
    m = _ALL_RE.search(spf_txt)
    all_mech = m.group(1) if m else "~all"
    policy_map = {"+all": "pass", "~all": "softfail", "-all": "fail", "?all": "neutral"}
    policy = policy_map.get(all_mech, "neutral")
    permissive = all_mech in ("+all", "?all") or ("redirect=" in spf_txt and not spf_txt.strip().endswith(("-all", "~all")))
    return {"present": True, "policy": policy, "ip_ranges": ip_ranges,
            "third_party": third_party, "permissive": permissive, "raw": spf_txt}


def parse_dmarc(txt_records: List[str]) -> Dict:
    dmarc = ""
    for t in txt_records:
        if t.strip().lower().startswith("v=dmarc1"):
            dmarc = t.strip()
            break
    if not dmarc:
        return {"present": False, "policy": "missing", "permissive": True, "raw": ""}
    fields = dict()
    for part in dmarc.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            fields[k.strip().lower()] = v.strip().lower()
    policy = fields.get("p", "none")
    permissive = policy in ("none",) or fields.get("sp", policy) in ("none",)
    return {"present": True, "policy": policy, "permissive": permissive, "raw": dmarc,
            "rua": fields.get("rua", ""), "pct": fields.get("pct", "")}


DKIM_SELECTORS = [
    "default", "selector1", "selector2", "selector3", "google", "k1", "k2", "s1", "s2",
    "s3", "dkim", "mandrill", "everlytickey1", "everlytickey2", "protonmail", "mxvault",
    "selector", "smtp", "mail", "email", "zoho", "c1", "c2", "c3", "o1", "o2", "o3",
]


async def check_dkim(domain: str, selectors: Optional[List[str]] = None) -> List[str]:
    r = _resolver()
    found = []
    for sel in (selectors or DKIM_SELECTORS):
        name = f"{sel}._domainkey.{domain}"
        try:
            async with limiter("dns", rate=80, burst=120):
                await r.resolve(name, "TXT", raise_on_no_answer=False, lifetime=3)
            found.append(sel)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except (dns.exception.DNSException, OSError):
            continue
    return found


async def dns_policy_for(host: str) -> Dict:
    """Aggregate SPF/DMARC/DKIM posture for a host (usually the root domain)."""
    recs = await resolve_all(host)
    txts = recs.get("TXT", [])
    spf = parse_spf(txts)
    dmarc_recs = []
    try:
        r = _resolver()
        ans = await r.resolve("_dmarc." + host, "TXT", raise_on_no_answer=False, lifetime=4)
        dmarc_recs = [b"".join(s.encode() if isinstance(s, str) else s for s in rr.strings).decode("utf-8", "replace")
                      for rr in ans]
    except (dns.exception.DNSException, OSError):
        dmarc_recs = []
    dmarc = parse_dmarc(dmarc_recs)
    dkim = await check_dkim(host)
    return {
        "spf": spf,
        "dmarc": dmarc,
        "dkim_selectors": dkim,
        "dkim_present": bool(dkim),
        "records": recs,
    }
