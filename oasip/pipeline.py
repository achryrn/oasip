"""Orchestration engine.

Runs the module DAG with an in-process asyncio worker model, task logging,
per-stage failure isolation, and host enrichment between discovery stages.
(PostgreSQL + Celery/Redis remain supported through OASIP_DATABASE_URL and
the optional celery_app.py tasks; the default path needs no infra.)
"""
from __future__ import annotations

import traceback
from typing import Callable, Dict, List, Optional

from . import repos
from .config import Config, get_config
from .db import dbsync, init_db
from .modules import (breach_module, code_module, correlate_module,
                      ct_module, dns_module, fingerprint_module,
                      identity_module, risk_module)
from .modules.context import ScanContext
from .services import resolver
from .util import gather_limited, is_subdomain, log, sanitize_host

ALL_MODULES = ["dns", "ct", "code", "identity", "breach", "fingerprint",
               "correlate", "risk"]
ALIASES = {"all": ALL_MODULES, "infra": ["fingerprint"], "dns_enum": ["dns"],
           "dns": ["dns"], "ct": ["ct"], "repos": ["code"], "breach": ["breach"],
           "identity": ["identity"], "correlate": ["correlate"], "risk": ["risk"]}

MODULE_FUNCS = {
    "dns": dns_module.run,
    "ct": ct_module.run,
    "code": code_module.run,
    "identity": identity_module.run,
    "breach": breach_module.run,
    "fingerprint": fingerprint_module.run,
    "correlate": correlate_module.run,
    "risk": risk_module.run,
}


class AuthorizationError(Exception):
    """Raised when a scan is attempted without an explicit authorization flag."""


def parse_modules(modules: List[str]) -> List[str]:
    out: List[str] = []
    for m in modules:
        for resolved in ALIASES.get(m.lower(), [m.lower()]):
            if resolved in MODULE_FUNCS and resolved not in out:
                out.append(resolved)
    return out


async def _resolve_extra_hosts(ctx: ScanContext) -> int:
    """Resolve hostnames discovered by modules after the DNS stage (e.g. from
    code scanning) and persist them so fingerprinting sees the full surface."""
    existing = {h.hostname for h in (await dbsync(repos.list_hosts, ctx.scan_id))}
    pending = [h for h in ctx.extra_hosts if sanitize_host(h) not in existing
               and is_subdomain(sanitize_host(h), ctx.target)]
    added = 0

    async def process(hostname: str) -> None:
        nonlocal added
        recs = await resolver.resolve_all(hostname)
        ips = list(dict.fromkeys(recs.get("A", []) + recs.get("AAAA", [])))
        cname = (recs.get("CNAME") or [None])[0] or None
        if not ips and not cname:
            return
        await dbsync(repos.upsert_host, ctx.scan_id, hostname,
                     is_root=False, source="code", ips=ips,
                     cname_target=cname, dns_records=recs)
        added += 1

    await gather_limited([process(h) for h in pending[:2000]], ctx.cfg.concurrency)
    return added


async def run_scan(target: str, org_name: Optional[str] = None,
                   modules: Optional[List[str]] = None,
                   cfg: Optional[Config] = None,
                   on_progress: Optional[Callable[[str, str, str], None]] = None,
                   wordlist: Optional[str] = None) -> int:
    cfg = cfg or get_config()
    if not cfg.accept_risk:
        raise AuthorizationError(
            "Refusing to scan without authorization. Re-run with --authorized "
            "(or set OASIP_AUTHORIZED=1) after confirming you own or are "
            "explicitly permitted to test this target.")
    if wordlist:
        cfg.stopwords_file = __import__("pathlib").Path(wordlist)
    target = sanitize_host(target)
    mods = parse_modules(modules or ALL_MODULES)
    init_db()

    scan_id = await dbsync(repos.create_scan, target, org_name, mods)
    ctx = ScanContext(scan_id=scan_id, target=target, org_name=org_name, cfg=cfg)
    log().info("scan %d started: target=%s org=%s modules=%s",
               scan_id, target, org_name or "-", ",".join(mods))

    completed: List[str] = []
    failed: List[str] = []
    stats_all: Dict[str, Dict] = {}
    overall = None

    ordered = [m for m in ["dns", "ct", "code", "identity", "breach",
                           "fingerprint", "correlate", "risk"] if m in mods]
    for module in ordered:
        await dbsync(repos.log_task, scan_id, module, "running")
        if on_progress:
            on_progress(module, "running", "")
        try:
            if module == "code":
                stats = await MODULE_FUNCS["code"](ctx)
                added = await _resolve_extra_hosts(ctx)
                stats["resolved_extra"] = added
                log().info("scan %d code stage found %d new hosts", scan_id, added)
            else:
                stats = await MODULE_FUNCS[module](ctx)
            stats_all[module] = stats or {}
            completed.append(module)
            await dbsync(repos.log_task, scan_id, module, "done",
                         message=f"ok ({len(stats or {})} metrics)")
            if on_progress:
                on_progress(module, "done", "")
        except Exception as exc:
            failed.append(module)
            log().error("module %s failed: %r\n%s", module, exc,
                        traceback.format_exc(limit=6))
            await dbsync(repos.log_task, scan_id, module, "failed",
                         message=str(exc)[:400])
            if on_progress:
                on_progress(module, "failed", str(exc)[:200])

    # summary -----------------------------------------------------------------
    hosts_n = len(await dbsync(repos.list_hosts, scan_id))
    ips_n = len(await dbsync(repos.list_ips, scan_id))
    findings_n = len(await dbsync(repos.list_findings, scan_id))
    takeovers = await dbsync(repos.list_takeovers, scan_id)
    shadows = await dbsync(repos.list_shadows, scan_id)
    summary = {
        "hosts": hosts_n, "ips": ips_n, "findings": findings_n,
        "takeovers": len(takeovers), "shadow_assets": len(shadows),
        "modules_completed": completed, "modules_failed": failed,
        "stats": stats_all,
    }
    risk_stats = stats_all.get("risk", {})
    overall = risk_stats.get("overall")
    status = "partial" if failed else "done"
    if not completed:
        status = "failed"
    await dbsync(repos.finish_scan, scan_id, status, summary,
                 float(overall) if overall is not None else None,
                 None if not failed else "; ".join(failed))
    log().info("scan %d finished: status=%s hosts=%d ips=%d findings=%d score=%s",
               scan_id, status, hosts_n, ips_n, findings_n, overall)
    if on_progress:
        on_progress("scan", "done", f"score={overall} status={status}")
    return scan_id
