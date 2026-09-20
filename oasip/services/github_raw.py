"""Raw file content fetch for GitHub search hits (added to github module
surface without bloating it)."""
from __future__ import annotations

from typing import Optional

import httpx

from ..config import get_config
from ..limits import limiter
from ..util import UA, log


async def raw_file(repo_full: str, path: str, sha: Optional[str] = None) -> Optional[str]:
    cfg = get_config()
    url = f"https://raw.githubusercontent.com/{repo_full}/HEAD/{path}"
    headers = {"User-Agent": UA}
    if cfg.github_token:
        headers["Authorization"] = f"Bearer {cfg.github_token}"
    try:
        async with limiter("github", rate=5000 / 3600 if cfg.github_token else 10 / 60, burst=5):
            async with httpx.AsyncClient(timeout=cfg.http_timeout,
                                         follow_redirects=True, headers=headers) as client:
                resp = await client.get(url)
                if resp.status_code == 404 and sha:
                    resp = await client.get(f"https://raw.githubusercontent.com/{repo_full}/{sha}/{path}")
                if resp.status_code != 200:
                    return None
                return resp.text[:500_000]
    except Exception as exc:
        log().debug("raw fetch %s failed: %r", url, exc)
        return None
