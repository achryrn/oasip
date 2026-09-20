"""Module 9 - Report Exporters.

Self-contained HTML (no external deps), Markdown, and STIX 2.1 JSON output
generated from the scan database. Report output mirrors a real external
pentest recon phase writeup.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from jinja2 import Template

from . import repos
from .config import get_config
from .util import safe_filename

FENCE = chr(96) * 3  # three backticks

HTML_TEMPLATE = Template(r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OASIP Recon Report - {{ data.scope }}</title>
<style>
:root{--ink:#1a2332;--mut:#5b6b83;--bg:#f4f6fa;--card:#fff;--line:#dfe5ef;
--crit:#b3261e;--high:#e37400;--med:#8a6d00;--low:#377e3f;--info:#3a6ea5}
*{box-sizing:border-box}body{font:14px/1.55 -apple-system,'Segoe UI',Roboto,Arial,sans-serif;color:var(--ink);background:var(--bg);margin:0;padding:32px}
.wrap{max-width:1080px;margin:0 auto}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:36px 0 10px;border-bottom:2px solid var(--line);padding-bottom:6px}
h3{font-size:15px;margin:18px 0 6px}.sub{color:var(--mut);margin-bottom:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:10px 0;box-shadow:0 1px 2px rgba(20,30,60,.05)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;text-align:center}
.kpi .v{font-size:26px;font-weight:700}.kpi .l{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse;font-size:13px;margin:8px 0}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:#eef1f7;color:var(--mut);font-weight:600}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;color:#fff}
.critical,.b-critical{background:var(--crit)}.high,.b-high{background:var(--high)}
.medium,.b-medium{background:var(--med)}.low,.b-low{background:var(--low)}
.info,.b-info{background:var(--info)}.none{background:#7c8798}
code{background:#eef1f7;padding:1px 5px;border-radius:4px;font-size:12px}
pre{background:#10161f;color:#d8e0ee;padding:12px;border-radius:8px;overflow:auto;font-size:12px}
.foot{margin-top:40px;color:var(--mut);font-size:12px;border-top:1px solid var(--line);padding-top:10px}
.score-big{font-size:44px;font-weight:800}
</style></head><body><div class="wrap">
<h1>External Attack Surface Reconnaissance Report</h1>
<div class="sub">OASIP &bull; scope: <code>{{ data.scope }}</code> &bull; generated {{ data.generated }}
&bull; target org: {{ data.org_name or "n/a" }}</div>

<div class="grid">
<div class="kpi"><div class="score-big" style="color:var(--med)">{{ data.overall }}</div><div class="l">Overall risk /100</div></div>
<div class="kpi"><div class="v">{{ data.hosts|length }}</div><div class="l">Hosts</div></div>
<div class="kpi"><div class="v">{{ data.ips|length }}</div><div class="l">IPs</div></div>
<div class="kpi"><div class="v">{{ data.findings|length }}</div><div class="l">Findings</div></div>
<div class="kpi"><div class="v">{{ data.certs }}</div><div class="l">Certificates</div></div>
<div class="kpi"><div class="v">{{ data.takeovers|length }}</div><div class="l">Takeovers</div></div>
</div>

<h2>Executive Summary</h2>
<div class="card">{{ data.exec_summary }}</div>

{% if data.findings %}
<h2>Key Findings</h2>
{% for f in data.findings[:60] %}
<div class="card"><span class="badge b-{{ f.severity }}">{{ f.severity }}</span>
<strong>{{ f.title }}</strong>
{% if f.evidence %}<pre>{{ f.evidence }}</pre>{% endif %}</div>
{% endfor %}
{% endif %}

<h2>Assets</h2>
<table><thead><tr><th>Hostname</th><th>IPs</th><th>ASN</th><th>Status</th><th>Server</th><th>Score</th></tr></thead>
<tbody>
{% for h in data.hosts %}<tr><td><code>{{ h.hostname }}</code></td>
<td>{{ h.ips|join(", ") }}</td><td>{{ h.asn or "" }}</td>
<td>{{ h.http_status or "" }}</td><td>{{ h.server_header or "" }}</td><td>{{ h.score }}</td></tr>{% endfor %}
</tbody></table>

<h2>Breach Exposure</h2>
<table><thead><tr><th>Subject</th><th>Breach</th><th>Exposure</th><th>Pwned</th><th>Date</th></tr></thead><tbody>
{% for b in data.breaches %}<tr><td>{{ b.subject_name }}</td><td>{{ b.breach_name }}</td>
<td><span class="badge b-{{ b.pw_exposure }}">{{ b.pw_exposure }}</span></td>
<td>{{ b.pwn_count or "" }}</td><td>{{ b.breach_date or (b.added_date or "") }}</td></tr>{% endfor %}
</tbody></table>

<h2>Repository Findings</h2>
<table><thead><tr><th>Repo</th><th>Path</th><th>Type</th><th>Tool</th></tr></thead><tbody>
{% for r in data.repos %}<tr><td>{{ r.repo_url }}</td><td>{{ r.file_path or "" }}</td>
<td>{{ r.secret_type or "" }}</td><td>{{ r.tool }}</td></tr>{% endfor %}
</tbody></table>

<h2>Technology & CVEs</h2>
<table><thead><tr><th>Asset</th><th>Technology</th><th>Version</th><th>CVSS</th><th>CVEs</th></tr></thead><tbody>
{% for t in data.techs %}<tr><td>{{ t.asset_name }}</td><td>{{ t.name }}</td><td>{{ t.version }}</td>
<td>{{ t.cvss_max or "" }}</td><td>{{ t.cve_ids|join(", ") }}</td></tr>{% endfor %}
</tbody></table>

{% if data.takeovers %}
<h2>Subdomain Takeover Candidates</h2>
<table><thead><tr><th>Hostname</th><th>CNAME</th><th>Service</th><th>Status</th></tr></thead><tbody>
{% for t in data.takeovers %}<tr><td><code>{{ t.hostname }}</code></td><td>{{ t.cname_target or "" }}</td>
<td>{{ t.service or "" }}</td><td>{{ t.status }}</td></tr>{% endfor %}
</tbody></table>
{% endif %}

<div class="foot">Generated by OASIP (OSINT &amp; Attack Surface Intelligence Platform) &mdash; authorized testing only.</div>
</div></body></html>""")


def build_report(scan_id: int) -> Dict:
    scan = repos.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"scan {scan_id} not found")
    hosts = repos.list_hosts(scan_id)
    ips = repos.list_ips(scan_id)
    certs = repos.list_certs(scan_id)
    findings = repos.list_findings(scan_id)
    breaches = repos.list_breaches(scan_id)
    repos_f = repos.list_repo_findings(scan_id)
    techs = repos.list_technologies(scan_id)
    takeovers = repos.list_takeovers(scan_id)
    shadows = repos.list_shadows(scan_id)
    employees = repos.list_employees(scan_id)
    emails = repos.list_emails(scan_id)

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_sorted = sorted(findings, key=lambda f: sev_order.get(f.severity, 5))

    return {
        "scan_id": scan_id,
        "scope": scan.target,
        "org_name": scan.org_name,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "overall": round(scan.overall_score or 0),
        "hosts": [{"hostname": h.hostname, "ips": h.ips or [], "asn": h.asn,
                   "http_status": h.http_status, "server_header": h.server_header,
                   "score": round(h.score or 0), "spf": h.spf_policy,
                   "dmarc": h.dmarc_policy, "dkim": h.dkim_present,
                   "cert_expiry": h.cert_expiry, "wildcard": h.wildcard_dns}
                  for h in hosts],
        "ips": [{"ip": i.ip, "asn": i.asn, "org": i.org_name, "ports": i.ports or [],
                 "score": round(i.score or 0)} for i in ips],
        "certs": len(certs),
        "findings": [{"severity": f.severity, "kind": f.kind, "title": f.title,
                      "evidence": f.evidence, "asset": f.asset_name}
                     for f in findings_sorted],
        "breaches": [{"subject_name": b.subject_name, "breach_name": b.breach_name,
                      "pw_exposure": b.pw_exposure, "pwn_count": b.pwn_count,
                      "breach_date": b.breach_date, "added_date": b.added_date}
                     for b in breaches],
        "repos": [{"repo_url": r.repo_url, "file_path": r.file_path,
                   "secret_type": r.secret_type, "tool": r.tool, "query": r.query_used,
                   "preview": r.secret_preview} for r in repos_f],
        "techs": [{"asset_name": t.asset_name, "name": t.name, "version": t.version,
                   "cvss_max": t.cvss_max, "cve_ids": t.cve_ids or []} for t in techs],
        "takeovers": [{"hostname": t.hostname, "cname_target": t.cname_target,
                       "service": t.service, "status": t.status} for t in takeovers],
        "shadows": [{"hostname": s.hostname, "reason": s.reason} for s in shadows],
        "employees": [{"name": e.name, "email": e.email, "title": e.title,
                       "executive": e.is_executive} for e in employees],
        "emails": [{"email": e.email, "status": e.status} for e in emails],
        "exec_summary": (
            f"Reconnaissance of {scan.target} identified {len(hosts)} hosts across "
            f"{len(ips)} unique IPs, {len(certs)} certificates, and {len(findings)} findings "
            f"({len([f for f in findings if f.severity in ('critical', 'high')])} critical/high). "
            f"Overall exposure score: {round(scan.overall_score or 0)}/100. "
            f"{len(takeovers)} subdomain takeover candidate(s), {len(shadows)} shadow-IT "
            f"asset(s), {len(breaches)} breach record(s), {len(repos_f)} repository secret "
            f"exposure(s)."),
    }


def render_html(data: Dict) -> str:
    return HTML_TEMPLATE.render(data=data)


def render_markdown(data: Dict) -> str:
    lines = [
        f"# External Attack Surface Reconnaissance Report: {data['scope']}",
        "",
        f"- **Generated:** {data['generated']}",
        f"- **Target org:** {data['org_name'] or 'n/a'}",
        f"- **Overall risk score:** {data['overall']}/100",
        f"- **Assets:** {len(data['hosts'])} hosts, {len(data['ips'])} IPs",
        "",
        "## Executive Summary",
        "",
        data["exec_summary"],
        "",
        "## Key Findings",
        "",
    ]
    for f in data["findings"][:60]:
        lines.append(f"- **[{f['severity']}]** {f['title']}")
        if f.get("evidence"):
            lines.append(f"  {FENCE}")
            lines.append(f"  {f['evidence'][:300]}")
            lines.append(f"  {FENCE}")
    lines += ["", "## Hosts", "", "| Hostname | IPs | ASN | HTTP | Server | Score |",
              "|---|---|---|---|---|---|"]
    for h in data["hosts"]:
        lines.append(f"| {h['hostname']} | {', '.join(h['ips'][:6])} | {h['asn'] or ''} | "
                     f"{h['http_status'] or ''} | {h['server_header'] or ''} | {h['score']} |")
    lines += ["", "## Breaches", "", "| Subject | Breach | Exposure | Pwned | Date |", "|---|---|---|---|---|"]
    for b in data["breaches"]:
        lines.append(f"| {b['subject_name']} | {b['breach_name']} | {b['pw_exposure']} | "
                     f"{b['pwn_count'] or ''} | {b['breach_date'] or b['added_date'] or ''} |")
    lines += ["", "## Repository Findings", "", "| Repo | Path | Type | Tool |", "|---|---|---|---|"]
    for r in data["repos"][:80]:
        lines.append(f"| {r['repo_url']} | {r['file_path'] or ''} | {r['secret_type'] or ''} | {r['tool']} |")
    lines += ["", "## Technology & CVEs", "", "| Asset | Tech | Version | CVSS | CVEs |", "|---|---|---|---|---|"]
    for t in data["techs"][:80]:
        lines.append(f"| {t['asset_name']} | {t['name']} | {t['version']} | {t['cvss_max'] or ''} | "
                     f"{', '.join(t['cve_ids'][:5])} |")
    if data["takeovers"]:
        lines += ["", "## Subdomain Takeover Candidates", "", "| Hostname | CNAME | Service | Status |",
                  "|---|---|---|---|"]
        for t in data["takeovers"]:
            lines.append(f"| {t['hostname']} | {t['cname_target'] or ''} | {t['service'] or ''} | {t['status']} |")
    return "\n".join(lines) + "\n"


def render_stix(data: Dict) -> Dict:
    """STIX 2.1 bundle: identity, domain-name, ipv4-addr, x509-certificate,
    vulnerability, indicator, observed-data and relationships."""
    bundle_id = "bundle--" + str(uuid.uuid4())
    objects = []
    identity_id = "identity--" + str(uuid.uuid4())
    objects.append({
        "type": "identity", "id": identity_id,
        "created": data["generated"], "modified": data["generated"],
        "name": data["org_name"] or data["scope"],
        "identity_class": "organization",
    })
    domain_ids: Dict[str, str] = {}
    for h in data["hosts"][:500]:
        dom_id = "domain-name--" + str(uuid.uuid4())
        domain_ids[h["hostname"]] = dom_id
        objects.append({"type": "domain-name", "id": dom_id,
                        "value": h["hostname"],
                        "created": data["generated"], "modified": data["generated"]})
        for ip in h["ips"][:4]:
            ip_id = "ipv4-addr--" + str(uuid.uuid4())
            objects.append({"type": "ipv4-addr", "id": ip_id, "value": ip,
                            "created": data["generated"], "modified": data["generated"]})
            objects.append({"type": "relationship", "id": "relationship--" + str(uuid.uuid4()),
                            "relationship_type": "resolves-to",
                            "source_ref": dom_id, "target_ref": ip_id,
                            "created": data["generated"], "modified": data["generated"]})
    vuln_ids: Dict[str, str] = {}
    for t in data["techs"]:
        for cve in (t["cve_ids"] or [])[:3]:
            if cve in vuln_ids:
                continue
            vid = "vulnerability--" + str(uuid.uuid4())
            vuln_ids[cve] = vid
            objects.append({"type": "vulnerability", "id": vid, "name": cve,
                            "created": data["generated"], "modified": data["generated"]})
            if t["asset_name"] in domain_ids:
                objects.append({"type": "relationship",
                                "id": "relationship--" + str(uuid.uuid4()),
                                "relationship_type": "has-vulnerability",
                                "source_ref": domain_ids[t["asset_name"]],
                                "target_ref": vid,
                                "created": data["generated"], "modified": data["generated"]})
    obs_id = "observed-data--" + str(uuid.uuid4())
    obs_refs = list(domain_ids.values())
    objects.append({"type": "observed-data", "id": obs_id,
                    "created": data["generated"], "modified": data["generated"],
                    "first_observed": data["generated"],
                    "last_observed": data["generated"],
                    "number_observed": max(1, len(obs_refs)),
                    "object_refs": obs_refs})
    if data["findings"]:
        ind_id = "indicator--" + str(uuid.uuid4())
        objects.append({"type": "indicator", "id": ind_id,
                        "created": data["generated"], "modified": data["generated"],
                        "name": f"OASIP exposure indicators for {data['scope']}",
                        "pattern": "[domain-name:value = '" + data["scope"] + "']",
                        "valid_from": data["generated"],
                        "indicator_types": ["malicious-activity"]
                        if any(f["severity"] in ("critical", "high") for f in data["findings"])
                        else ["unknown"]})
    return {"type": "bundle", "id": bundle_id, "spec_version": "2.1",
            "objects": objects}


def write_reports(scan_id: int, formats: Optional[List[str]] = None,
                  out_dir: Optional[Path] = None) -> List[Path]:
    formats = formats or ["html", "md", "stix"]
    data = build_report(scan_id)
    out_dir = out_dir or get_config().reports_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    base = out_dir / f"oasip_{safe_filename(data['scope'])}_{scan_id}"
    written = []
    if "html" in formats:
        p = base.with_suffix(".html")
        p.write_text(render_html(data), encoding="utf-8")
        written.append(p)
    if "md" in formats or "markdown" in formats:
        p = base.with_suffix(".md")
        p.write_text(render_markdown(data), encoding="utf-8")
        written.append(p)
    if "stix" in formats or "json" in formats:
        p = base.with_suffix(".stix2.json")
        p.write_text(json.dumps(render_stix(data), indent=2), encoding="utf-8")
        written.append(p)
    return written
