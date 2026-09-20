"""GitHub REST client: code search, org members, public repos, commit emails."""
from __future__ import annotations

from typing import Dict, List, Optional

import httpx

from ..config import get_config
from ..limits import limiter
from ..util import UA, log

BASE = "https://api.github.com"


def _auth_headers() -> Dict[str, str]:
    cfg = get_config()
    if cfg.github_token:
        return {"Authorization": f"Bearer {cfg.github_token}",
                "Accept": "application/vnd.github+json", "User-Agent": "OASIP"}
    return {"User-Agent": "OASIP"}


def _rate() -> float:
    # GitHub: 10 req/min unauthenticated, 5000/hr authed
    return 5000 / 3600 if get_config().github_token else 10 / 60


async def _get(path: str, params: Optional[Dict] = None) -> Dict:
    try:
        async with limiter("github", rate=_rate(), burst=5):
            async with httpx.AsyncClient(timeout=get_config().http_timeout) as client:
                resp = await client.get(BASE + path, params=params, headers=_auth_headers())
                if resp.status_code in (401, 403):
                    log().warning("GitHub %s -> %s", resp.status_code, path)
                    return {}
                if resp.status_code == 404:
                    return {}
                resp.raise_for_status()
                return resp.json()
    except Exception as exc:
        log().debug("GitHub %s failed: %r", path, exc)
        return {}


async def search_code(query: str, per_page: int = 20) -> List[Dict]:
    data = await _get("/search/code",
                      {"q": query, "per_page": per_page, "sort": "indexed"})
    return data.get("items", []) if isinstance(data, dict) else []


async def org_members(org: str) -> List[Dict]:
    data = await _get(f"/orgs/{org}/members", {"per_page": 100})
    return data if isinstance(data, list) else []


async def org_repos(org: str) -> List[Dict]:
    data = await _get(f"/orgs/{org}/repos",
                      {"per_page": 100, "type": "public", "sort": "updated"})
    return data if isinstance(data, list) else []


async def repo_commits(owner: str, repo: str, per_page: int = 100) -> List[Dict]:
    data = await _get(f"/repos/{owner}/{repo}/commits", {"per_page": per_page})
    return data if isinstance(data, list) else []


from .github_raw import raw_file  # noqa: E402,F401  (re-export for modules)


def commits_emails(commits: List[Dict]) -> List[str]:
    import re
    out = []
    for c in commits:
        raw = c.get("commit", {})
        for who in ("author", "committer"):
            em = (raw.get(who) or {}).get("email") or ""
            if em and re.match(r"^[^@]+@[^@]+$", em):
                out.append(em)
    return list(dict.fromkeys(out))
