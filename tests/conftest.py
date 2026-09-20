import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture()
def tmp_env(tmp_path, monkeypatch):
    """Isolated config pointing at a temporary SQLite DB."""
    from oasip.config import Config, set_config
    cfg = Config(
        database_url="sqlite:///" + str(tmp_path / "test.db").replace("\\", "/"),
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        stopwords_file=Path(__file__).resolve().parent.parent
        / "wordlists" / "default_subdomains.txt",
        accept_risk=True,
    )
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    cfg.reports_dir.mkdir(parents=True, exist_ok=True)
    set_config(cfg)
    from oasip.db import init_db
    init_db()
    return cfg
