"""Module 3 - Code Repository Scanner.

GitHub code search with target-scoped queries, secret classification,
internal-hostname discovery, and optional TruffleHog git-history scanning
of the organization's public repositories. GitLab/Bitbucket clients follow
the same pattern (keys/secrets must be configured).
"""
from __future__ import annotations

from typing import Dict, List, Optional

from .. import repos, secrets as secret_util
from ..db import dbsync
from ..services import github, trufflehog
from ..util import is_subdomain, log, sanitize_host

from .context import ScanContext

QUERIES = [
    "org:{org} filename:.env",
    "org:{org} password",
    "org:{org} api_key",
    "org:{org} secret",
    "org:{org} BEGIN RSA PRIVATE KEY",
    '"orgdomain" password',
    '"orgdomain" secret',
    '"orgdomain" token',
    '"orgdomain" smtp',
    '"orgdomain" jdbc',
    '"orgdomain" BEGIN RSA PRIVATE KEY',
    '"orgdomain" mysql',
    '"orgdomain" postgres',
    '"orgdomain" mongodb',
    '"orgdomain" aws_access_key_id',
    '"orgdomain" .env',
    '"internal.{domain}"',
    '"10.0.0." "{domain}"',
]


def _queries_for(ctx: ScanContext) -> List[str]:
    org = ctx.org_name or ""
    domain = ctx.target
    qs = []
    for q in QUERIES:
        qs.append(q.replace("{org}", org.strip() or "MISSING")
                   .replace("orgdomain", domain)
                   .replace("{domain}", domain))
    if org:
        # dedupe the org- and domain-anchored variants where they collide
        pass
    return qs


async def run(ctx: ScanContext) -> Dict:
    cfg = ctx.cfg
    stats: Dict = {"findings": 0, "emails": 0, "new_hosts": 0, "repos_scanned": 0}
    seen_keys: set = set()

    async def handle_result(query: str, html_url: str, repo_full: str, path: str,
                            content: Optional[str], sha: str = "") -> None:
        if not content:
            return
        for item in secret_util.classify(content):
            key = f"{repo_full}:{path}:{item['type']}:{item['match'][:40]}"
            if key in seen_keys:
                continue
            seen_keys.add(key)
            severity = item["severity"]
            await dbsync(repos.add_repo_finding,
                         ctx.scan_id, f"https://github.com/{repo_full}",
                         repo_owner=repo_full.split("/")[0] if "/" in repo_full else "",
                         repo_name=repo_full.split("/")[1] if "/" in repo_full else repo_full,
                         tool="github-search", query_used=query, file_path=path,
                         secret_type=item["type"],
                         secret_preview=item["match"][:120],
                         commit_hash=sha or None)
            await dbsync(repos.add_finding, ctx.scan_id, "secret", severity,
                         f"{item['type']} exposed in {repo_full} ({path})",
                         {"query": query, "repo": repo_full, "path": path,
                          "type": item["type"]},
                         item["context"][:400], 20.0 if severity == "critical" else 5.0,
                         "repo", repo_full)
            stats["findings"] += 1
        # emails + internal hostnames inside the same content
        for em in secret_util.extract_emails(content):
            stats.setdefault("emails", 0)
            await dbsync(repos.upsert_email_candidate, ctx.scan_id, em,
                         employee_name="", status="suggested", source="github-code")
            stats["emails"] += 1
        for h in secret_util.extract_internal_hostnames(content, ctx.target):
            h = sanitize_host(h)
            if h and is_subdomain(h, ctx.target):
                await dbsync(repos.upsert_host, ctx.scan_id, h,
                             is_root=False, source="code",
                             ips=[])  # will be resolved by the pipeline enrich pass
                ctx.add_hosts([h], source="code")
                stats["new_hosts"] += 1
        for h in secret_util.extract_conn_string_targets(content):
            h = sanitize_host(h)
            if h and not h.endswith((".png", ".jpg", ".gif", ".svg", ".css", ".js")):
                await dbsync(repos.upsert_host, ctx.scan_id, h,
                             is_root=False, source="code", ips=[])
                ctx.add_hosts([h], source="code")
                stats["new_hosts"] += 1

    # ---- GitHub search ---------------------------------------------------
    queries = _queries_for(ctx)
    fetched_files = 0
    for query in queries:
        try:
            items = await github.search_code(query, per_page=15)
        except Exception as exc:
            log().debug("github search %r failed: %r", query, exc)
            continue
        for item in items[:15]:
            repo_full = (item.get("repository") or {}).get("full_name", "")
            path = item.get("path", "")
            url = item.get("html_url", "")
            if not repo_full:
                continue
            if fetched_files >= 250:
                break
            content = await github.raw_file(repo_full, path, item.get("sha"))
            fetched_files += 1
            if content is None:
                continue
            await handle_result(query, url, repo_full, path, content, sha=item.get("sha"))
        if fetched_files >= 250:
            log().info("github: file fetch cap reached (250)")
            break
    stats["queries_run"] = len(queries)
    stats["files_fetched"] = fetched_files

    # ---- TruffleHog over the org's public repos ---------------------------
    if ctx.org_name and trufflehog.available():
        try:
            repos_list = await github.org_repos(ctx.org_name.strip())
            repos_list = repos_list[:15]
            stats["org_repos"] = len(repos_list)
            for repo in repos_list:
                full = repo.get("full_name", "")
                if not full:
                    continue
                try:
                    res = await trufflehog.scan_repo(f"https://github.com/{full}")
                except Exception as exc:
                    log().debug("trufflehog %s failed: %r", full, exc)
                    continue
                for f in res:
                    await dbsync(repos.add_repo_finding, ctx.scan_id,
                                 f"https://github.com/{full}",
                                 repo_owner=full.split("/")[0], repo_name=full.split("/")[1],
                                 tool="trufflehog", file_path=f.get("target"),
                                 secret_type=f.get("secret_type"),
                                 secret_preview=f.get("secret"),
                                 commit_hash=f.get("commit"))
                    await dbsync(repos.add_finding, ctx.scan_id, "secret",
                                 "high" if f.get("verified") else "medium",
                                 f"TruffleHog: {f.get('secret_type')} in git history of {full}"
                                 + (" (VERIFIED)" if f.get("verified") else ""),
                                 {"repo": full, "verified": f.get("verified")},
                                 f.get("secret"), 20.0 if f.get("verified") else 5.0,
                                 "repo", full)
                    stats["findings"] += 1
                stats["repos_scanned"] += 1
        except Exception as exc:
            log().debug("trufflehog org pass failed: %r", exc)

    return stats
