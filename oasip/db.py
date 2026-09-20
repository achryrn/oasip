"""SQLAlchemy engine/session helpers.

Default storage is a zero-setup SQLite file. Point OASIP_DATABASE_URL at a
PostgreSQL URL (postgresql+psycopg2://...) to use the full stack; the rest of
OASIP is agnostic. All DB work runs off the event loop for async modules.
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from contextlib import contextmanager
from typing import Any, Callable

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_config

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="oasip-db")
_engine: "Engine | None" = None
_session_factory: "sessionmaker | None" = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        url = get_config().database_url
        kwargs: dict = {"future": True, "pool_pre_ping": True}
        if url.startswith("sqlite"):
            kwargs.update({"connect_args": {"check_same_thread": False}})
        _engine = create_engine(url, **kwargs)

        @event.listens_for(_engine, "connect")
        def _pragma(dbapi_connection, connection_record):  # pragma: no cover - sqlite only
            try:
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()
            except Exception:
                pass
    return _engine


def get_factory() -> sessionmaker:
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(bind=get_engine(), future=True, expire_on_commit=False)
    return _session_factory


def init_db() -> None:
    """Create tables. Idempotent."""
    from . import models  # noqa: F401  (register mappers)

    get_engine().connect().close()
    models.Base.metadata.create_all(get_engine())


@contextmanager
def session_scope():
    """Sync context manager yielding a Session (commit on success)."""
    factory = get_factory()
    s = factory()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def run_sync(fn: Callable, *args: Any, **kwargs: Any) -> asyncio.Future:
    """Run a sync DB function in the executor thread pool."""
    loop = asyncio.get_event_loop()
    return loop.run_in_executor(_executor, partial(fn, *args, **kwargs))


async def dbsync(fn: Callable, *args: Any, **kwargs: Any) -> Any:
    return await run_sync(fn, *args, **kwargs)
