"""Optional Celery/Redis task queue glue.

OASIP runs fully on the built-in asyncio pipeline; this module exists for
deployments that want distributed workers:

    pip install "celery[redis]"
    celery -A oasip.celery_app worker --loglevel=info
"""
from __future__ import annotations

try:
    from celery import Celery  # type: ignore
    from .config import get_config
    from .db import init_db
    from .pipeline import run_scan

    cfg = get_config()
    app = Celery(
        "oasip",
        broker=cfg.database_url.replace("postgresql", "redis") or "redis://localhost:6379/0",
        backend=cfg.database_url.replace("postgresql", "redis") or "redis://localhost:6379/0",
    )
    app.conf.update(task_track_started=True, worker_prefetch_multiplier=1)

    @app.task(name="oasip.scan")
    def scan_task(target: str, org_name: str = "", modules: list = None) -> int:
        import asyncio
        init_db()
        return asyncio.run(run_scan(target, org_name or None, modules or None))
except ImportError:  # celery not installed - importing this module is a no-op
    app = None  # type: ignore
