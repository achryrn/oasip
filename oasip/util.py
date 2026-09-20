"""Small shared helpers used across OASIP modules."""
from __future__ import annotations

import asyncio
import logging
import random
import re
import time
from typing import Any, Iterable, List, Optional, Sequence, TypeVar

T = TypeVar("T")

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 OASIP/0.1"
)


def log() -> logging.Logger:
    return logging.getLogger("oasip")


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def dedupe(seq: Iterable[T]) -> List[T]:
    seen: set = set()
    out: List[T] = []
    for item in seq:
        key = item if isinstance(item, (str, int, float, bool, tuple)) else repr(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def is_subdomain(host: str, domain: str) -> bool:
    h = host.lower().rstrip(".")
    d = domain.lower().rstrip(".")
    return h == d or h.endswith("." + d)


def split_name_value(nv: str) -> List[str]:
    """crt.sh returns SAN lists newline separated; sometimes with wildcards."""
    out = []
    for line in (nv or "").replace("\\n", "\n").split("\n"):
        s = line.strip().lower().rstrip(".")
        if s:
            out.append(s)
    return dedupe(out)


def sanitize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


def extract_emails(text: Optional[str]) -> List[str]:
    if not text:
        return []
    return dedupe([m.lower() for m in _EMAIL_RE.findall(text)])


def random_label(n: int = 10) -> str:
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def safe_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)


def sample(text: Optional[str], limit: int = 400) -> str:
    if not text:
        return ""
    text = " ".join(text.split())
    return text[:limit] + ("…" if len(text) > limit else "")


def aslist(v: Any) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        return [v]
    return [v]


def dict_get(d: dict, *keys: str, default: Any = None) -> Any:
    for k in keys:
        if isinstance(d, dict) and k in d:
            return d[k]
    return default


async def gather_limited(coros: List, limit: int) -> List[Any]:
    """Run coroutines with an upper concurrency bound, preserving order."""
    sem = asyncio.Semaphore(limit)
    results: List[Any] = [None] * len(coros)

    async def run(i: int, c) -> None:
        async with sem:
            results[i] = await c

    await asyncio.gather(*(run(i, c) for i, c in enumerate(coros)), return_exceptions=True)
    return results
