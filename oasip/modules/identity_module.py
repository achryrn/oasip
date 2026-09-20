"""Module 5 - Identity & Employee Mapping.

Public GitHub org members + commit-author emails feed an email-format
inference engine and permutation generator. An *opt-in* RCPT TO validation
step (guarded, rate-limited, no mail delivery) confirms candidate addresses
only when --smtp-probe is explicitly requested. LinkedIn enumeration is
generated as search queries, not scraping.
"""
from __future__ import annotations

import asyncio
import re
from typing import Dict, List, Optional, Tuple

from .. import repos
from ..db import dbsync
from ..services import github
from ..util import extract_emails, log

from .context import ScanContext

EXEC_TITLES = ("ceo", "cfo", "cto", "ciso", "cso", "cio", "coo", "cpo", "cmo",
               "vice president", "vp of", "director of", "head of", "chief")

LINKEDIN_DORKS = [
    'site:linkedin.com/in "{org}"',
    'site:linkedin.com/in "{org}" "security"',
    'site:linkedin.com/in "{org}" "engineer"',
    'site:linkedin.com/in "{org}" "manager"',
    'site:linkedin.com/in "{org}" "founder"',
    'site:linkedin.com/in "at {org}"',
]

EMAIL_FORMATS = [
    ("first.last", lambda f, l: f"{f}.{l}"),
    ("flast", lambda f, l: f"{f[0]}{l}"),
    ("f.last", lambda f, l: f"{f[0]}.{l}"),
    ("firstl", lambda f, l: f"{f}{l[0]}"),
    ("first_last", lambda f, l: f"{f}_{l}"),
    ("first", lambda f, l: f"{f}"),
    ("last.first", lambda f, l: f"{l}.{f}"),
    ("firstlast", lambda f, l: f"{f}{l}"),
]


def infer_email_format(emails: List[str]) -> Optional[str]:
    """Infer the org's email convention from observed addresses."""
    if len(emails) < 2:
        return None
    counts: Dict[str, int] = {}
    for em in emails:
        user = em.split("@")[0].lower()
        if "." in user:
            counts["first.last"] = counts.get("first.last", 0) + 1
            counts["last.first"] = counts.get("last.first", 0) + 1
        elif len(user) < 4:
            counts["first"] = counts.get("first", 0) + 1
        elif user[-1].isalpha() and user[-2:].isdigit():
            counts["first.last"] = counts.get("first.last", 0) + 1
    best = max(counts.items(), key=lambda kv: kv[1]) if counts else None
    return best[0] if best and best[1] >= max(2, len(emails) // 2) else "first.last"


def _split_name(name: str) -> Tuple[str, str]:
    parts = [p for p in re.split(r"[\s.,_-]+", name.strip()) if p]
    if not parts:
        return "", ""
    if len(parts) == 1:
        return parts[0].lower(), ""
    return parts[0].lower(), parts[-1].lower()


def generate_permutations(name: str, domain: str, fmt: Optional[str]) -> List[str]:
    first, last = _split_name(name)
    if not first or not last:
        return []
    out = []
    builder = dict(EMAIL_FORMATS).get(fmt or "first.last") or EMAIL_FORMATS[0][1]
    out.append(builder(first, last) + "@" + domain)
    # always include the two most common alternatives
    for alt in ("first.last", "flast"):
        if alt != (fmt or "first.last"):
            out.append(dict(EMAIL_FORMATS)[alt](first, last) + "@" + domain)
    return list(dict.fromkeys(x for x in out if re.match(r"^[a-z0-9._-]+@", x)))


async def run(ctx: ScanContext) -> Dict:
    cfg = ctx.cfg
    stats: Dict = {"employees": 0, "emails": 0, "permutations": 0}
    collected_emails: List[str] = []
    org = (ctx.org_name or "").strip()

    # ---- GitHub org members ----------------------------------------------
    if org:
        try:
            members = await github.org_members(org)
        except Exception as exc:
            log().debug("org members failed: %r", exc)
            members = []
        for m in members:
            login = m.get("login", "")
            name = m.get("name") or login
            if not name:
                continue
            await dbsync(repos.upsert_employee, ctx.scan_id, name,
                         github_user=login, source="github-org")
            stats["employees"] += 1

    # ---- commit author emails from the org's public repos -----------------
    if org:
        try:
            repos_list = (await github.org_repos(org))[:10]
        except Exception as exc:
            log().debug("org repos failed: %r", exc)
            repos_list = []
        for repo in repos_list:
            full = repo.get("full_name", "")
            if not full or "/" not in full:
                continue
            try:
                commits = await github.repo_commits(*full.split("/", 1))
            except Exception:
                continue
            for em in github.commits_emails(commits):
                if em.lower().endswith("@" + ctx.target):
                    collected_emails.append(em)
                    await dbsync(repos.upsert_email_candidate, ctx.scan_id, em,
                                 status="suggested", source="github-commits")
    if collected_emails:
        await dbsync(repos.upsert_employee, ctx.scan_id,
                     ctx.target.split(".")[0].title() + " (commit correlation)",
                     email=collected_emails[0] if len(collected_emails) == 1 else None,
                     source="correlation")
    fmt = infer_email_format(collected_emails)
    stats["email_format"] = fmt or "unknown"

    # ---- permutation engine ------------------------------------------------
    employees = await dbsync(repos.list_employees, ctx.scan_id)
    for emp in employees:
        if emp.name:
            for cand in generate_permutations(emp.name, ctx.target, fmt):
                await dbsync(repos.upsert_email_candidate, ctx.scan_id, cand,
                             employee_name=emp.name, status="suggested",
                             source="engine")
                stats["permutations"] += 1

    # ---- executive tagging --------------------------------------------------
    for emp in employees:
        title = (emp.title or "").lower()
        if any(t in title for t in EXEC_TITLES):
            await dbsync(repos.upsert_employee, ctx.scan_id, emp.name,
                         is_executive=True)

    # ---- opt-in RCPT TO validation (guardrailed) ---------------------------
    if cfg.smtp_probe:
        stats["smtp_probed"] = await _smtp_probe(ctx)

    # ---- LinkedIn enumeration queries (generated, not scraped) --------------
    if org:
        dork_queries = [d.replace("{org}", org) for d in LINKEDIN_DORKS]
        await dbsync(repos.add_finding, ctx.scan_id, "identity", "info",
                     f"LinkedIn enumeration queries ({len(dork_queries)})",
                     {"dorks": dork_queries}, "", 0.0, "domain", ctx.target)
    stats["emails"] = len(collected_emails)
    return stats


async def _smtp_probe(ctx: ScanContext) -> Dict:
    """Confirm candidate emails by RCPT TO probing.

    Guardrails: only when explicitly enabled, sequential probes with a
    minimum delay, a hard cap on candidates, no DATA command, standard
    MAIL FROM with an invalid placeholder (nothing is delivered).
    """
    from ..services.resolver import resolve_a, nslookup
    from ..util import random_label

    candidates = [c for c in (await dbsync(repos.list_emails, ctx.scan_id))
                  if c.status == "suggested"][:40]
    if not candidates:
        return {"checked": 0, "confirmed": 0}
    mx_hosts = await nslookup(ctx.target)
    mx_host = ""
    for h in mx_hosts:
        ips = await resolve_a(h)
        if ips:
            mx_host, mx_ip = h, ips[0]
            break
    else:
        log().warning("smtp probe: no usable MX for %s - skipping", ctx.target)
        return {"checked": 0, "confirmed": 0}
    log().warning("SMTP RCPT probing MX %s - only %d candidates, sequential, "
                  "no mail is sent", mx_host, len(candidates))
    confirmed = 0
    checked = 0
    for cand in candidates:
        ok = await _rcpt_probe(mx_ip, cand.email)
        checked += 1
        if ok is True:
            confirmed += 1
            await dbsync(repos.upsert_email_candidate, ctx.scan_id, cand.email,
                         status="confirmed", source="smtp-rcpt")
            await dbsync(repos.add_finding, ctx.scan_id, "identity", "medium",
                         f"Confirmed employee email candidate {cand.email}",
                         {"email": cand.email}, "", 0.0, "email", cand.email)
        elif ok is False:
            await dbsync(repos.upsert_email_candidate, ctx.scan_id, cand.email,
                         status="invalid", source="smtp-rcpt")
        await asyncio.sleep(4.0)  # minimal polite delay between probes
    return {"checked": checked, "confirmed": confirmed}


async def _rcpt_probe(mx_ip: str, email: str) -> Optional[bool]:
    """Connect, EHLO, MAIL FROM (invalid placeholder), RCPT TO, QUIT.

    Returns True (exists), False (rejected), None (inconclusive)."""
    import asyncio as _a
    try:
        reader, writer = await _a.wait_for(_a.open_connection(mx_ip, 25), timeout=10)
        banner = await reader.read(512)
        if not banner.startswith(b"220"):
            writer.close()
            return None
        writer.write(b"EHLO oasip.local\r\n")
        await reader.read(4096)
        writer.write(b"MAIL FROM:<probe.invalid@" + b"example.invalid>\r\n")
        await reader.read(4096)
        writer.write(f"RCPT TO:<{email}>\r\n".encode())
        resp = await reader.read(2048)
        writer.write(b"QUIT\r\n")
        try:
            await reader.read(512)
        except Exception:
            pass
        writer.close()
        code = int(resp[:3]) if resp[:3].isdigit() else 0
        if code == 250:
            return True
        if code in (550, 551, 553, 554):
            return False
        return None
    except Exception:
        return None
