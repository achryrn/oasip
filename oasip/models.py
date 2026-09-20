"""ORM models for one scan's full attack-surface picture."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, Column, DateTime, Float, ForeignKey,
                        Index, Integer, String, Text, UniqueConstraint)
from sqlalchemy.orm import declarative_base

Base = declarative_base()


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    target = Column(String(255), nullable=False, index=True)
    org_name = Column(String(255), nullable=True)
    status = Column(String(32), default="running")      # running|done|failed|partial
    modules_requested = Column(Text, default="")
    modules_completed = Column(Text, default="")
    started_at = Column(DateTime, default=_now)
    finished_at = Column(DateTime, nullable=True)
    overall_score = Column(Float, nullable=True)
    summary = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)

    @property
    def asset_count(self) -> int:
        return (self.summary or {}).get("hosts", 0)


class Host(Base):
    __tablename__ = "hosts"
    __table_args__ = (UniqueConstraint("scan_id", "hostname", name="uq_host_scan"),)

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True, nullable=False)
    hostname = Column(String(255), nullable=False)
    is_root = Column(Boolean, default=False)
    source = Column(String(32), default="")            # ct|brute|passivedns|root
    ips = Column(JSON, default=list)                   # [str]
    asn = Column(String(32), nullable=True)
    org_name = Column(String(255), nullable=True)
    country = Column(String(64), nullable=True)
    cname_target = Column(String(255), nullable=True)
    dns_records = Column(JSON, default=dict)
    spf_policy = Column(String(32), nullable=True)     # pass|softfail|neutral|fail|none
    spf_ip_ranges = Column(JSON, default=list)
    spf_third_party = Column(JSON, default=list)
    spf_permissive = Column(Boolean, default=False)
    dmarc_policy = Column(String(32), nullable=True)   # none|quarantine|reject|missing
    dmarc_permissive = Column(Boolean, default=False)
    dkim_present = Column(Boolean, default=False)
    wildcard_dns = Column(Boolean, default=False)
    cert_sha256 = Column(String(64), nullable=True)
    cert_issued_date = Column(String(24), nullable=True)
    cert_expiry = Column(String(24), nullable=True)
    cert_issuer = Column(String(255), nullable=True)
    http_status = Column(Integer, nullable=True)
    server_header = Column(String(255), nullable=True)
    techs = Column(JSON, default=list)
    score = Column(Float, default=0.0)


class IPAddress(Base):
    __tablename__ = "ip_addresses"
    __table_args__ = (UniqueConstraint("scan_id", "ip", name="uq_ip_scan"),)

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True, nullable=False)
    ip = Column(String(45), nullable=False)
    hostnames = Column(JSON, default=list)
    asn = Column(String(32), nullable=True)
    org_name = Column(String(255), nullable=True)
    isp = Column(String(255), nullable=True)
    country = Column(String(64), nullable=True)
    os_name = Column(String(64), nullable=True)
    ports = Column(JSON, default=list)
    banners = Column(JSON, default=list)
    http_headers = Column(JSON, default=dict)
    tls_config = Column(JSON, default=dict)
    ssh_keys = Column(JSON, default=list)
    cloud_provider = Column(String(64), nullable=True)
    cdn = Column(String(64), nullable=True)
    origin_exposed = Column(Boolean, default=False)
    techs = Column(JSON, default=list)
    score = Column(Float, default=0.0)


class Certificate(Base):
    __tablename__ = "certificates"
    __table_args__ = (UniqueConstraint("scan_id", "sha256", name="uq_cert_scan"),)

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True, nullable=False)
    sha256 = Column(String(64), nullable=False)
    crtsh_id = Column(Integer, nullable=True)
    domains = Column(JSON, default=list)
    issuer = Column(String(255), nullable=True)
    subject_org = Column(String(255), nullable=True)
    not_before = Column(String(24), nullable=True)
    not_after = Column(String(24), nullable=True)
    key_algo = Column(String(32), nullable=True)
    key_bits = Column(Integer, nullable=True)
    sig_algo = Column(String(64), nullable=True)
    is_wildcard = Column(Boolean, default=False)
    is_self_signed = Column(Boolean, default=False)
    reuse_count = Column(Integer, default=0)
    verified_ips = Column(JSON, default=list)
    source = Column(String(16), default="ct")          # ct|tls
    flags = Column(JSON, default=list)                 # ['weak-rsa','sha1',...]


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_finding_scan_sev", "scan_id", "severity"),)

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True, nullable=False)
    kind = Column(String(64), nullable=False)          # cve|secret|breach|dmarc|ssl|takeover|shadow|config|identity|infra
    severity = Column(String(16), nullable=False)      # critical|high|medium|low|info
    title = Column(String(512), nullable=False)
    detail = Column(JSON, default=dict)
    evidence = Column(Text, nullable=True)
    score_impact = Column(Float, default=0.0)
    asset_type = Column(String(16), nullable=True)     # host|ip|email|domain|repo|none
    asset_name = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=_now)


class Employee(Base):
    __tablename__ = "employees"
    __table_args__ = (UniqueConstraint("scan_id", "name", name="uq_emp_scan"),)

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True, nullable=False)
    name = Column(String(255), nullable=False)
    title = Column(String(255), nullable=True)
    department = Column(String(255), nullable=True)
    email = Column(String(255), nullable=True)
    email_format = Column(String(64), nullable=True)   # first.last / flast / ...
    source = Column(String(32), default="")
    linkedin_url = Column(String(512), nullable=True)
    github_user = Column(String(128), nullable=True)
    is_executive = Column(Boolean, default=False)


class EmailCandidate(Base):
    __tablename__ = "email_candidates"
    __table_args__ = (UniqueConstraint("scan_id", "email", name="uq_email_scan"),)

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True, nullable=False)
    employee_name = Column(String(255), default="")
    email = Column(String(255), nullable=False)
    status = Column(String(16), default="suggested")   # suggested|confirmed|invalid
    source = Column(String(32), default="engine")


class BreachRecord(Base):
    __tablename__ = "breach_records"
    __table_args__ = (UniqueConstraint("scan_id", "subject_name", "breach_name", name="uq_breach"),)

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True, nullable=False)
    subject_type = Column(String(16), default="domain")  # domain|email
    subject_name = Column(String(255), nullable=False)
    breach_name = Column(String(255), nullable=False)
    breach_date = Column(String(24), nullable=True)
    added_date = Column(String(24), nullable=True)
    pwn_count = Column(Integer, nullable=True)
    data_classes = Column(JSON, default=list)
    pw_exposure = Column(String(16), default="unknown")  # plaintext|hashed|none|unknown
    severity = Column(String(16), default="medium")
    source = Column(String(32), default="")


class RepoFinding(Base):
    __tablename__ = "repo_findings"
    __table_args__ = (Index("ix_repo_scan", "scan_id"),)

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True, nullable=False)
    repo_url = Column(String(512), nullable=False)
    repo_owner = Column(String(255), nullable=True)
    repo_name = Column(String(255), nullable=True)
    tool = Column(String(32), default="github-search")  # github-search|trufflehog|gitlab|bitbucket
    query_used = Column(String(255), nullable=True)
    file_path = Column(String(512), nullable=True)
    secret_type = Column(String(64), nullable=True)
    secret_preview = Column(String(255), nullable=True)
    commit_hash = Column(String(64), nullable=True)
    commit_author = Column(String(255), nullable=True)
    commit_email = Column(String(255), nullable=True)


class Technology(Base):
    __tablename__ = "technologies"
    __table_args__ = (UniqueConstraint("scan_id", "asset_name", "name", "version", name="uq_tech"),)

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True, nullable=False)
    asset_type = Column(String(16), default="host")
    asset_name = Column(String(255), nullable=False)
    name = Column(String(128), nullable=False)
    version = Column(String(64), default="")
    category = Column(String(64), default="")
    confidence = Column(Integer, default=100)
    evidence = Column(String(255), nullable=True)
    cvss_max = Column(Float, nullable=True)
    cve_ids = Column(JSON, default=list)


class SubdomainTakeover(Base):
    __tablename__ = "takeovers"
    __table_args__ = (UniqueConstraint("scan_id", "hostname", name="uq_takeover"),)

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True, nullable=False)
    hostname = Column(String(255), nullable=False)
    cname_target = Column(String(255), nullable=True)
    service = Column(String(64), nullable=True)
    fingerprint = Column(String(255), nullable=True)
    status = Column(String(16), default="potential")    # vulnerable|potential
    evidence = Column(Text, nullable=True)


class ShadowAsset(Base):
    __tablename__ = "shadow_assets"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True, nullable=False)
    hostname = Column(String(255), nullable=False)
    reason = Column(String(255), nullable=False)
    details = Column(JSON, default=dict)


class TaskLog(Base):
    __tablename__ = "task_logs"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True, nullable=False)
    module = Column(String(64), nullable=False)
    status = Column(String(16), default="running")      # running|done|failed|skipped
    started_at = Column(DateTime, default=_now)
    finished_at = Column(DateTime, nullable=True)
    detail = Column(JSON, default=dict)
    message = Column(Text, nullable=True)
