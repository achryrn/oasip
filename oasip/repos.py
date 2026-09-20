"""Persistence helpers: thin upsert functions used by modules (sync, run via db.dbsync)."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select

from . import models
from .db import session_scope
from .util import now_iso


def upsert_host(scan_id: int, hostname: str, **fields: Any) -> None:
    with session_scope() as s:
        row = s.execute(select(models.Host).where(
            models.Host.scan_id == scan_id, models.Host.hostname == hostname)).scalar_one_or_none()
        if row is None:
            row = models.Host(scan_id=scan_id, hostname=hostname)
            s.add(row)
        for k, v in fields.items():
            if v is not None:
                setattr(row, k, v)


def upsert_ip(scan_id: int, ip: str, **fields: Any) -> None:
    with session_scope() as s:
        row = s.execute(select(models.IPAddress).where(
            models.IPAddress.scan_id == scan_id, models.IPAddress.ip == ip)).scalar_one_or_none()
        if row is None:
            row = models.IPAddress(scan_id=scan_id, ip=ip)
            s.add(row)
        for k, v in fields.items():
            if v is not None:
                setattr(row, k, v)


def upsert_certificate(scan_id: int, sha256: str, **fields: Any) -> None:
    with session_scope() as s:
        row = s.execute(select(models.Certificate).where(
            models.Certificate.scan_id == scan_id,
            models.Certificate.sha256 == sha256)).scalar_one_or_none()
        if row is None:
            row = models.Certificate(scan_id=scan_id, sha256=sha256)
            s.add(row)
        for k, v in fields.items():
            if v is not None:
                setattr(row, k, v)


def add_finding(scan_id: int, kind: str, severity: str, title: str,
                detail: Optional[Dict] = None, evidence: Optional[str] = None,
                score_impact: float = 0.0, asset_type: Optional[str] = None,
                asset_name: Optional[str] = None) -> None:
    with session_scope() as s:
        s.add(models.Finding(scan_id=scan_id, kind=kind, severity=severity,
                             title=title[:500], detail=detail or {},
                             evidence=evidence, score_impact=score_impact,
                             asset_type=asset_type, asset_name=asset_name))


def upsert_employee(scan_id: int, name: str, **fields: Any) -> None:
    with session_scope() as s:
        row = s.execute(select(models.Employee).where(
            models.Employee.scan_id == scan_id, models.Employee.name == name)).scalar_one_or_none()
        if row is None:
            row = models.Employee(scan_id=scan_id, name=name)
            s.add(row)
        for k, v in fields.items():
            if v is not None:
                setattr(row, k, v)


def upsert_email_candidate(scan_id: int, email: str, **fields: Any) -> None:
    with session_scope() as s:
        row = s.execute(select(models.EmailCandidate).where(
            models.EmailCandidate.scan_id == scan_id,
            models.EmailCandidate.email == email)).scalar_one_or_none()
        if row is None:
            row = models.EmailCandidate(scan_id=scan_id, email=email)
            s.add(row)
        for k, v in fields.items():
            if v is not None:
                setattr(row, k, v)


def upsert_breach(scan_id: int, subject_name: str, breach_name: str, **fields: Any) -> None:
    with session_scope() as s:
        row = s.execute(select(models.BreachRecord).where(
            models.BreachRecord.scan_id == scan_id,
            models.BreachRecord.subject_name == subject_name,
            models.BreachRecord.breach_name == breach_name)).scalar_one_or_none()
        if row is None:
            row = models.BreachRecord(scan_id=scan_id, subject_name=subject_name,
                                      breach_name=breach_name)
            s.add(row)
        for k, v in fields.items():
            if v is not None:
                setattr(row, k, v)


def add_repo_finding(scan_id: int, repo_url: str, **fields: Any) -> None:
    with session_scope() as s:
        s.add(models.RepoFinding(scan_id=scan_id, repo_url=repo_url, **fields))


def upsert_technology(scan_id: int, asset_name: str, name: str, version: str = "",
                      **fields: Any) -> None:
    with session_scope() as s:
        row = s.execute(select(models.Technology).where(
            models.Technology.scan_id == scan_id,
            models.Technology.asset_name == asset_name,
            models.Technology.name == name,
            models.Technology.version == version)).scalar_one_or_none()
        if row is None:
            row = models.Technology(scan_id=scan_id, asset_name=asset_name,
                                    name=name, version=version)
            s.add(row)
        for k, v in fields.items():
            if v is not None:
                setattr(row, k, v)


def upsert_takeover(scan_id: int, hostname: str, **fields: Any) -> None:
    with session_scope() as s:
        row = s.execute(select(models.SubdomainTakeover).where(
            models.SubdomainTakeover.scan_id == scan_id,
            models.SubdomainTakeover.hostname == hostname)).scalar_one_or_none()
        if row is None:
            row = models.SubdomainTakeover(scan_id=scan_id, hostname=hostname)
            s.add(row)
        for k, v in fields.items():
            if v is not None:
                setattr(row, k, v)


def add_shadow(scan_id: int, hostname: str, reason: str, details: Optional[Dict] = None) -> None:
    with session_scope() as s:
        s.add(models.ShadowAsset(scan_id=scan_id, hostname=hostname,
                                 reason=reason, details=details or {}))


def log_task(scan_id: int, module: str, status: str = "running",
             message: Optional[str] = None, detail: Optional[Dict] = None) -> None:
    with session_scope() as s:
        row = s.execute(select(models.TaskLog).where(
            models.TaskLog.scan_id == scan_id,
            models.TaskLog.module == module)).scalar_one_or_none()
        from datetime import datetime, timezone
        if row is None:
            row = models.TaskLog(scan_id=scan_id, module=module)
            s.add(row)
        row.status = status
        row.message = message
        if detail:
            row.detail = {**(row.detail or {}), **detail}
        if status in ("done", "failed", "skipped"):
            row.finished_at = datetime.now(timezone.utc)


def create_scan(target: str, org_name: Optional[str], modules: List[str]) -> int:
    with session_scope() as s:
        row = models.Scan(target=target, org_name=org_name, status="running",
                          modules_requested=",".join(modules))
        s.add(row)
        s.flush()
        return row.id


def finish_scan(scan_id: int, status: str, summary: Optional[Dict] = None,
                overall_score: Optional[float] = None, error: Optional[str] = None) -> None:
    from datetime import datetime, timezone
    with session_scope() as s:
        row = s.get(models.Scan, scan_id)
        if row is None:
            return
        row.status = status
        row.finished_at = datetime.now(timezone.utc)
        if summary is not None:
            row.summary = summary
        if overall_score is not None:
            row.overall_score = overall_score
        if error:
            row.error = error


def get_scan(scan_id: int) -> Optional[models.Scan]:
    with session_scope() as s:
        row = s.get(models.Scan, scan_id)
        if row is None:
            return None
        # detach
        s.expunge(row)
        return row


def list_hosts(scan_id: int) -> List[models.Host]:
    with session_scope() as s:
        rows = s.execute(select(models.Host).where(
            models.Host.scan_id == scan_id).order_by(models.Host.hostname)).scalars().all()
        return [r for r in rows]


def list_ips(scan_id: int) -> List[models.IPAddress]:
    with session_scope() as s:
        rows = s.execute(select(models.IPAddress).where(
            models.IPAddress.scan_id == scan_id).order_by(models.IPAddress.ip)).scalars().all()
        return [r for r in rows]


def list_certs(scan_id: int) -> List[models.Certificate]:
    with session_scope() as s:
        rows = s.execute(select(models.Certificate).where(
            models.Certificate.scan_id == scan_id)).scalars().all()
        return [r for r in rows]


def list_findings(scan_id: int) -> List[models.Finding]:
    with session_scope() as s:
        rows = s.execute(select(models.Finding).where(
            models.Finding.scan_id == scan_id).order_by(models.Finding.severity)).scalars().all()
        return [r for r in rows]


def list_breaches(scan_id: int) -> List[models.BreachRecord]:
    with session_scope() as s:
        rows = s.execute(select(models.BreachRecord).where(
            models.BreachRecord.scan_id == scan_id)).scalars().all()
        return [r for r in rows]


def list_employees(scan_id: int) -> List[models.Employee]:
    with session_scope() as s:
        rows = s.execute(select(models.Employee).where(
            models.Employee.scan_id == scan_id)).scalars().all()
        return [r for r in rows]


def list_emails(scan_id: int) -> List[models.EmailCandidate]:
    with session_scope() as s:
        rows = s.execute(select(models.EmailCandidate).where(
            models.EmailCandidate.scan_id == scan_id)).scalars().all()
        return [r for r in rows]


def list_repo_findings(scan_id: int) -> List[models.RepoFinding]:
    with session_scope() as s:
        rows = s.execute(select(models.RepoFinding).where(
            models.RepoFinding.scan_id == scan_id)).scalars().all()
        return [r for r in rows]


def list_technologies(scan_id: int) -> List[models.Technology]:
    with session_scope() as s:
        rows = s.execute(select(models.Technology).where(
            models.Technology.scan_id == scan_id)).scalars().all()
        return [r for r in rows]


def list_takeovers(scan_id: int) -> List[models.SubdomainTakeover]:
    with session_scope() as s:
        rows = s.execute(select(models.SubdomainTakeover).where(
            models.SubdomainTakeover.scan_id == scan_id)).scalars().all()
        return [r for r in rows]


def list_shadows(scan_id: int) -> List[models.ShadowAsset]:
    with session_scope() as s:
        rows = s.execute(select(models.ShadowAsset).where(
            models.ShadowAsset.scan_id == scan_id)).scalars().all()
        return [r for r in rows]


def list_scans(limit: int = 50) -> List[Dict]:
    with session_scope() as s:
        rows = s.execute(select(models.Scan).order_by(
            models.Scan.id.desc()).limit(limit)).scalars().all()
        return [{"id": r.id, "target": r.target, "org_name": r.org_name,
                 "status": r.status, "started_at": str(r.started_at),
                 "finished_at": str(r.finished_at) if r.finished_at else None,
                 "overall_score": r.overall_score,
                 "summary": r.summary} for r in rows]
