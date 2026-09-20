"""Module 4 - Breach Intelligence.

Domain-level breach posture from Have I Been Pwned, paste/breach mirrors via
IntelX, and per-email checks when a paid HIBP tier is configured. Records are
classified by credential exposure type (plaintext > hashed > none) and
recency.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List

from .. import repos
from ..db import dbsync
from ..services import hibp, intelx
from ..util import log

from .context import ScanContext

_REVIEW_DAYS = 365


def _severity(exposure: str, added_date: str, pwn_count=None) -> str:
    sev = {"plaintext": "high", "hashed": "medium", "none": "info",
           "unknown": "medium"}.get(exposure, "medium")
    try:
        added = datetime.strptime((added_date or "")[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if added > datetime.now(timezone.utc) - timedelta(days=_REVIEW_DAYS):
            sev = "high" if sev != "critical" else sev
    except ValueError:
        pass
    return sev


async def run(ctx: ScanContext) -> Dict:
    cfg = ctx.cfg
    stats: Dict = {"records": 0, "findings": 0}
    target = ctx.target

    # ---- domain-level breach posture (HIBP) ------------------------------
    try:
        breaches = await hibp.domain_search(target)
    except Exception as exc:
        log().debug("HIBP failed: %r", exc)
        breaches = []
    stats["hibp_breaches"] = len(breaches)
    plaintext_seen = 0
    for b in breaches:
        name = b.get("Name") or b.get("name") or "unknown"
        added = b.get("AddedDate") or ""
        exposure = hibp.classify_pw_exposure(b.get("DataClasses", []))
        sev = _severity(exposure, added, b.get("PwnCount"))
        if exposure == "plaintext":
            plaintext_seen += 1
        await dbsync(repos.upsert_breach, ctx.scan_id, target, name,
                     subject_type="domain",
                     breach_date=(b.get("BreachDate") or "")[:10],
                     added_date=(added or "")[:10],
                     pwn_count=b.get("PwnCount"),
                     data_classes=b.get("DataClasses", []),
                     pw_exposure=exposure, severity=sev, source="hibp")
        stats["records"] += 1
        await dbsync(repos.add_finding, ctx.scan_id, "breach", sev,
                     f"Domain {target} present in breach '{name}' "
                     f"(exposure: {exposure}, pwned: {b.get('PwnCount')})",
                     {"breach": name, "exposure": exposure,
                      "data_classes": b.get("DataClasses", [])},
                     added[:10], 20.0 if exposure == "plaintext" else 5.0,
                     "domain", target)
        stats["findings"] += 1

    # ---- paste / darkweb mirror search (IntelX) --------------------------
    intel_terms = [f'"{target}"', f'@{target}']
    for term in intel_terms:
        try:
            res = await intelx.search(term, maxresults=20)
        except Exception as exc:
            log().debug("intelx failed: %r", exc)
            continue
        for item in res:
            total = item.get("totalresults", 0)
            if total:
                await dbsync(repos.add_finding, ctx.scan_id, "breach", "info",
                             f"IntelX: {total} results for '{term}' (paste/breach mirrors)",
                             {"term": term, "total": total}, "", 0.0, "domain", target)
                stats["findings"] += 1
            for rec in item.get("records", [])[:5]:
                await dbsync(repos.upsert_breach, ctx.scan_id, target, "IntelX:" + (rec.get("name") or term)[:200],
                             subject_type="domain", breach_date=(rec.get("date") or "")[:10],
                             pw_exposure="unknown", severity="low", source="intelx")
                stats["records"] += 1

    # ---- per-email checks (paid tier only) --------------------------------
    emails: List[str] = []
    try:
        for em in (await dbsync(repos.list_emails, ctx.scan_id)):
            if em.status == "confirmed":
                emails.append(em.email)
        for emp in (await dbsync(repos.list_employees, ctx.scan_id)):
            if emp.email:
                emails.append(emp.email)
    except Exception:
        pass
    emails = list(dict.fromkeys(emails))[:40]
    stats["emails_checked"] = 0
    for email in emails:
        if not cfg.hibp_key:
            break
        try:
            hits = await hibp.breached_account(email)
        except Exception:
            continue
        if not hits:
            continue
        stats["emails_checked"] += 1
        for b in hits[:10]:
            name = b.get("Name", "unknown")
            exposure = hibp.classify_pw_exposure(b.get("DataClasses", []))
            sev = _severity(exposure, b.get("AddedDate") or "")
            await dbsync(repos.upsert_breach, ctx.scan_id, email, name,
                         subject_type="email",
                         breach_date=(b.get("BreachDate") or "")[:10],
                         added_date=(b.get("AddedDate") or "")[:10],
                         pwn_count=b.get("PwnCount"),
                         data_classes=b.get("DataClasses", []),
                         pw_exposure=exposure, severity=sev, source="hibp-email")
            await dbsync(repos.add_finding, ctx.scan_id, "breach", sev,
                         f"Employee email {email} exposed in '{name}' ({exposure})",
                         {"email": email, "breach": name, "exposure": exposure},
                         "", 20.0 if exposure == "plaintext" else 5.0,
                         "email", email)
            stats["findings"] += 1
    stats["plaintext_domains"] = plaintext_seen
    return stats
