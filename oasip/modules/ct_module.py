"""Module 2 - Certificate Transparency Mining.

Turns crt.sh result sets into certificate records: identity fingerprints,
chain metadata (issuer, org fields, key/signature algorithms), weakness
flags (expired/expiring, short RSA, SHA-1/MD5, self-signed, wildcard),
and reuse detection across discovered hostnames.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict

from .. import repos
from ..certutil import flags_for, identity_fingerprint, parse_der
from ..db import dbsync
from ..services import crtsh
from ..util import is_subdomain, log, split_name_value

from .context import ScanContext


async def run(ctx: ScanContext) -> Dict:
    cfg = ctx.cfg
    target = ctx.target
    rows = await crtsh.query(target, expand=True, limit=8000)
    log().info("ct: %d raw certificate rows for %s", len(rows), target)

    # aggregate by identity fingerprint (serial|issuer|dates|sans)
    groups: Dict[str, Dict] = {}
    order: List[str] = []
    for row in rows:
        ident = identity_fingerprint(
            row.get("serial_number"), row.get("issuer_name"),
            (row.get("not_before") or ""), split_name_value(row.get("name_value", "")))
        if ident not in groups:
            groups[ident] = {
                "identity": ident,
                "crtsh_ids": [row.get("id")],
                "domains": split_name_value(row.get("name_value", "")),
                "issuer": row.get("issuer_name"),
                "subject_org": None,
                "not_before": (row.get("not_before") or "")[:19],
                "not_after": (row.get("not_after") or "")[:19],
                "key_algo": None, "key_bits": None, "sig_algo": None,
                "wildcard": any(d.startswith("*.") for d in split_name_value(row.get("name_value", ""))),
                "self_signed": False, "deep": False,
            }
            order.append(ident)
        else:
            g = groups[ident]
            g["domains"] = list(dict.fromkeys(g["domains"] + split_name_value(row.get("name_value", ""))))
            if not g["wildcard"]:
                g["wildcard"] = any(d.startswith("*.") for d in split_name_value(row.get("name_value", "")))
            g["crtsh_ids"].append(row.get("id"))
    stats = {"unique_certs": len(groups)}

    # deep analysis: fetch a bounded sample and read the actual certificate
    deep_list = [groups[k] for k in order[: cfg.deep_cert_limit]]
    for g in deep_list:
        cert_id = g["crtsh_ids"][0]
        der = await crtsh.fetch_pem(cert_id)
        if not der:
            continue
        cert = parse_der(der)
        if not cert:
            continue
        g["deep"] = True
        g.update({
            "subject_org": cert["org"] or None,
            "key_algo": cert["key_algo"],
            "key_bits": cert["key_bits"],
            "sig_algo": cert["sig_algo"],
            "wildcard": cert["wildcard"],
            "self_signed": cert["self_signed"],
            "real_sha256": cert["sha256"],
        })
        stats["deep_analyzed"] = stats.get("deep_analyzed", 0) + 1

    # reuse: same identity covering many hostnames
    reuse: Dict[str, List[str]] = {}
    for g in groups.values():
        names = [d for d in g["domains"] if is_subdomain(d, target)]
        if len(names) > 1:
            reuse[g["identity"]] = names

    # persist + findings
    now = datetime.now(timezone.utc)
    findings = []
    for ident in order:
        g = groups[ident]
        await dbsync(repos.upsert_certificate, ctx.scan_id, ident,
                     crtsh_id=g["crtsh_ids"][0], domains=g["domains"],
                     issuer=g["issuer"], subject_org=g["subject_org"],
                     not_before=g["not_before"], not_after=g["not_after"],
                     key_algo=g["key_algo"], key_bits=g["key_bits"],
                     sig_algo=g["sig_algo"], is_wildcard=g["wildcard"],
                     is_self_signed=g["self_signed"],
                     reuse_count=len(reuse.get(ident, [])),
                     source="ct")
        if not g["deep"]:
            continue
        flags = set(flags_for(g))
        g["flags"] = sorted(flags)
        for flag in flags:
            if flag in ("expired", "expiring"):
                findings.append(("ssl", "high" if flag == "expired" else "medium",
                                 f"Certificate {'expired' if flag == 'expired' else 'expiring within 30 days'} for {','.join(g['domains'][:4])}",
                                 {"cert": g["identity"], "not_after": g["not_after"]},
                                 g["not_after"], 10.0, "domain", ",".join(g["domains"][:2])))
            elif flag == "weak-rsa":
                findings.append(("ssl", "high", f"Certificate with weak RSA key ({g['key_bits']} bits) for {g['domains'][0]}",
                                 {"bits": g["key_bits"], "cert": g["identity"]}, "", 5.0, "domain", g["domains"][0]))
            elif flag == "weak-signature":
                findings.append(("ssl", "high", f"Certificate signed with {g['sig_algo']} for {g['domains'][0]}",
                                 {"sig": g["sig_algo"]}, "", 5.0, "domain", g["domains"][0]))
            elif flag == "self-signed":
                findings.append(("ssl", "medium", f"Self-signed certificate on {g['domains'][0]}",
                                 {"cert": g["identity"]}, "", 5.0, "domain", g["domains"][0]))
    for (kind, sev, title, detail, ev, imp, atype, aname) in findings:
        await dbsync(repos.add_finding, ctx.scan_id, kind, sev, title, detail, ev, imp, atype, aname)
    stats["findings"] = len(findings)
    stats["reuse_groups"] = len(reuse)

    # mine SAN hostnames into the asset pool for later stages
    mined: List[str] = []
    for g in groups.values():
        for d in g["domains"]:
            if is_subdomain(d, target):
                mined.append(d)
    ctx.add_hosts(mined, source="ct")
    stats["mined_hosts"] = len(set(mined))
    return stats
