"""FastAPI application exposing scan state + the Recharts dashboard."""
from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .. import repos
from ..config import get_config
from ..db import init_db
from ..pipeline import run_scan
from ..util import log

STATIC = Path(__file__).parent / "static"

app = FastAPI(title="OASIP Dashboard", version="0.1.0")


class ScanRequest(BaseModel):
    target: str
    org_name: Optional[str] = None
    modules: Optional[List[str]] = None
    authorized: bool = False
    wordlist: Optional[str] = None


@app.on_event("startup")
def _startup() -> None:
    init_db()


def _load_scan(scan_id: int) -> Dict:
    scan = repos.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, f"scan {scan_id} not found")
    return {
        "id": scan.id, "target": scan.target, "org_name": scan.org_name,
        "status": scan.status, "overall_score": scan.overall_score,
        "summary": scan.summary, "error": scan.error,
        "modules_requested": scan.modules_requested,
        "started_at": str(scan.started_at),
        "finished_at": str(scan.finished_at) if scan.finished_at else None,
    }


@app.get("/api/scan/{scan_id}/all")
def scan_all(scan_id: int) -> Dict:
    init_db()
    base = _load_scan(scan_id)
    base["hosts"] = [{"hostname": h.hostname, "ips": h.ips or [], "asn": h.asn,
                      "org_name": h.org_name, "source": h.source,
                      "http_status": h.http_status, "server_header": h.server_header,
                      "score": round(h.score or 0, 1), "wildcard": h.wildcard_dns,
                      "dmarc": h.dmarc_policy, "spf": h.spf_policy}
                     for h in repos.list_hosts(scan_id)]
    base["ips"] = [{"ip": i.ip, "asn": i.asn, "org_name": i.org_name,
                    "ports": i.ports or [], "cloud_provider": i.cloud_provider,
                    "score": round(i.score or 0, 1)} for i in repos.list_ips(scan_id)]
    base["findings"] = [{"id": f.id, "kind": f.kind, "severity": f.severity,
                         "title": f.title, "detail": f.detail, "asset": f.asset_name,
                         "score_impact": f.score_impact}
                        for f in repos.list_findings(scan_id)]
    base["breaches"] = [{"subject_name": b.subject_name, "breach_name": b.breach_name,
                         "pw_exposure": b.pw_exposure, "pwn_count": b.pwn_count,
                         "added_date": b.added_date, "breach_date": b.breach_date,
                         "severity": b.severity} for b in repos.list_breaches(scan_id)]
    base["repos"] = [{"repo_url": r.repo_url, "file_path": r.file_path,
                      "secret_type": r.secret_type, "tool": r.tool,
                      "secret_preview": r.secret_preview} for r in repos.list_repo_findings(scan_id)]
    base["techs"] = [{"asset_name": t.asset_name, "name": t.name, "version": t.version,
                      "cvss_max": t.cvss_max, "cve_ids": t.cve_ids or []}
                     for t in repos.list_technologies(scan_id)]
    base["certs"] = [{"not_before": c.not_before, "not_after": c.not_after,
                      "issuer": c.issuer, "domains": (c.domains or [])[:5],
                      "is_wildcard": c.is_wildcard, "is_self_signed": c.is_self_signed}
                     for c in repos.list_certs(scan_id)]
    base["takeovers"] = [{"hostname": t.hostname, "cname_target": t.cname_target,
                          "service": t.service, "status": t.status}
                         for t in repos.list_takeovers(scan_id)]
    base["shadows"] = [{"hostname": s.hostname, "reason": s.reason}
                       for s in repos.list_shadows(scan_id)]
    base["employees"] = [{"name": e.name, "email": e.email, "title": e.title,
                          "is_executive": e.is_executive} for e in repos.list_employees(scan_id)]
    base["emails"] = [{"email": e.email, "status": e.status}
                      for e in repos.list_emails(scan_id)]
    # heatmap bucket counts
    buckets = {"0-24": 0, "25-49": 0, "50-74": 0, "75-100": 0}
    for h in base["hosts"]:
        s = h["score"]
        buckets["0-24" if s < 25 else "25-49" if s < 50 else "50-74" if s < 75 else "75-100"] += 1
    base["heatmap"] = buckets
    base["certs_by_month"] = _certs_by_month(base["certs"])
    return base


def _certs_by_month(certs: List[Dict]) -> List[Dict]:
    counts: Dict[str, int] = {}
    for c in certs:
        month = (c.get("not_before") or "")[:7]
        if month:
            counts[month] = counts.get(month, 0) + 1
    return [{"month": k, "issued": v} for k, v in sorted(counts.items())]


@app.get("/api/scans")
def scans() -> List[Dict]:
    init_db()
    return repos.list_scans(50)


@app.get("/api/scan/{scan_id}")
def scan_meta(scan_id: int) -> Dict:
    init_db()
    return _load_scan(scan_id)


@app.post("/api/scan")
def start_scan(req: ScanRequest) -> JSONResponse:
    from dataclasses import replace

    cfg = get_config()
    if not req.authorized and not cfg.accept_risk:
        raise HTTPException(400, "authorized=true required - only scan targets you own "
                                 "or are explicitly permitted to test")
    if req.authorized and not cfg.accept_risk:
        cfg = replace(cfg, accept_risk=True)

    def worker() -> None:
        asyncio.run(run_scan(req.target, req.org_name, req.modules, cfg=cfg,
                             wordlist=req.wordlist))

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    return JSONResponse({"message": "scan started", "target": req.target})


app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(str(STATIC / "index.html"))
