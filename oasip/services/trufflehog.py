"""TruffleHog subprocess wrapper (git history secret scanning).

Requires the 'trufflehog' binary on PATH. Skips gracefully when absent.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from typing import Dict, List, Optional

from ..util import log


def available() -> bool:
    return shutil.which("trufflehog") is not None


async def _run(args: List[str], timeout: int = 900) -> List[Dict]:
    if not available():
        log().info("trufflehog binary not found - skipping history scan")
        return []
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    findings = []
    try:
        while True:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout)
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                verdict = obj.get("Verified") or obj.get("verified") or False
                findings.append({
                    "tool": "trufflehog",
                    "verified": bool(verdict),
                    "secret_type": obj.get("DetectorName") or obj.get("secret_type"),
                    "target": obj.get("SourceMetadata", {}).get("Data", {}).get("Github", {}).get("file",
                             obj.get("source_metadata", {})),
                    "commit": obj.get("SourceMetadata", {}).get("Data", {}).get("Github", {}).get("commit",
                              obj.get("commit", "")),
                    "secret": (obj.get("Raw") or obj.get("secret") or "")[:120],
                })
            except json.JSONDecodeError:
                continue
    except asyncio.TimeoutError:
        log().warning("trufflehog timed out")
    finally:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        await proc.wait()
    return findings


async def scan_github_org(org: str) -> List[Dict]:
    return await _run(["trufflehog", "github", "--org", org, "--json"])


async def scan_repo(url: str) -> List[Dict]:
    return await _run(["trufflehog", "git", url, "--json"])
