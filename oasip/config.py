"""Configuration: environment variables + optional .env file (no extra deps)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip().strip('"').strip("'")
            os.environ.setdefault(key, val)
    except OSError:
        pass


@dataclass
class Config:
    # --- storage ---------------------------------------------------------
    database_url: str = "sqlite:///oasip.db"
    data_dir: Path = Path("data")
    reports_dir: Path = Path("reports")
    stopwords_file: Path = Path("wordlists/default_subdomains.txt")

    # --- API keys (all optional) -----------------------------------------
    shodan_key: str = ""
    censys_id: str = ""
    censys_secret: str = ""
    binaryedge_key: str = ""
    virustotal_key: str = ""
    securitytrails_key: str = ""
    hackertarget_key: str = ""
    github_token: str = ""
    hibp_key: str = ""
    intelx_key: str = ""
    dehashed_email: str = ""
    dehashed_key: str = ""
    leakcheck_key: str = ""

    # --- behaviour ---------------------------------------------------------
    http_timeout: float = 12.0
    dns_timeout: float = 6.0
    dns_servers: list = field(default_factory=lambda: [
        "8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"])
    concurrency: int = 24            # module-level worker pool
    dns_concurrency: int = 60        # resolution fan-out
    max_hosts: int = 5000            # hard ceiling on enumerated hosts
    deep_cert_limit: int = 250       # max certs for full key-level analysis
    probe_timeout: float = 10.0
    smtp_probe: bool = False         # RCPT TO probing - OFF by default (guardrailed)
    ct_stream_interval: int = 300
    max_breach_records: int = 500
    max_repo_findings: int = 1000
    accept_risk: bool = False        # --authorized equivalent (env: OASIP_AUTHORIZED=1)
    verbose: bool = False

    @classmethod
    def load(cls, env_path: str = ".env") -> "Config":
        _load_dotenv(Path(env_path))
        env = os.environ

        def kv(name: str, default: str = "") -> str:
            return env.get(name, default).strip()

        cfg = cls(
            database_url=env.get("OASIP_DATABASE_URL", "sqlite:///oasip.db"),
            data_dir=Path(env.get("OASIP_DATA_DIR", "data")),
            reports_dir=Path(env.get("OASIP_REPORTS_DIR", "reports")),
            stopwords_file=Path(env.get("OASIP_WORDLIST", "wordlists/default_subdomains.txt")),
            shodan_key=kv("SHODAN_API_KEY"),
            censys_id=kv("CENSYS_API_ID"),
            censys_secret=kv("CENSYS_API_SECRET"),
            binaryedge_key=kv("BINARYEDGE_API_KEY"),
            virustotal_key=kv("VIRUSTOTAL_API_KEY"),
            securitytrails_key=kv("SECURITYTRAILS_API_KEY"),
            hackertarget_key=kv("HACKERTARGET_API_KEY"),
            github_token=kv("GITHUB_TOKEN"),
            hibp_key=kv("HIBP_API_KEY"),
            intelx_key=kv("INTELX_API_KEY"),
            dehashed_email=kv("DEHASHED_EMAIL"),
            dehashed_key=kv("DEHASHED_API_KEY"),
            leakcheck_key=kv("LEAKCHECK_API_KEY"),
            http_timeout=float(env.get("OASIP_HTTP_TIMEOUT", "12")),
            dns_timeout=float(env.get("OASIP_DNS_TIMEOUT", "6")),
            dns_servers=[s for s in env.get("OASIP_DNS_SERVERS", "8.8.8.8,1.1.1.1,9.9.9.9,208.67.222.222").split(",") if s],
            concurrency=int(env.get("OASIP_CONCURRENCY", "24")),
            dns_concurrency=int(env.get("OASIP_DNS_CONCURRENCY", "60")),
            max_hosts=int(env.get("OASIP_MAX_HOSTS", "5000")),
            deep_cert_limit=int(env.get("OASIP_DEEP_CERT_LIMIT", "250")),
            probe_timeout=float(env.get("OASIP_PROBE_TIMEOUT", "10")),
            smtp_probe=env.get("OASIP_SMTP_PROBE", "").lower() in ("1", "yes", "true"),
            ct_stream_interval=int(env.get("OASIP_CT_STREAM_INTERVAL", "300")),
            max_breach_records=int(env.get("OASIP_MAX_BREACH_RECORDS", "500")),
            max_repo_findings=int(env.get("OASIP_MAX_REPO_FINDINGS", "1000")),
            accept_risk=env.get("OASIP_AUTHORIZED", "").lower() in ("1", "yes", "true"),
            verbose=env.get("OASIP_VERBOSE", "").lower() in ("1", "yes", "true"),
        )
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        cfg.reports_dir.mkdir(parents=True, exist_ok=True)
        return cfg


_config: "Config | None" = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = Config.load()
    return _config


def set_config(cfg: Config) -> None:
    global _config
    _config = cfg
