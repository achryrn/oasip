"""OASIP command-line interface.

Examples:
  oasip init-db
  oasip scan example.com --org "Example Corp" --authorized --modules dns,ct
  oasip scan example.com --authorized --modules all --report
  oasip dashboard --port 8000
  oasip report --latest --format html,md,stix
  oasip ct-stream example.com --interval 300
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__, repos
from .config import Config, get_config, set_config
from .db import init_db
from .util import setup_logging


def _cfg_from_args(args, cfg: Config) -> Config:
    if getattr(args, "verbose", False):
        cfg.verbose = True
    if getattr(args, "authorized", False):
        cfg.accept_risk = True
    if getattr(args, "smtp_probe", False):
        cfg.smtp_probe = True
    if getattr(args, "concurrency", None) is not None:
        cfg.concurrency = args.concurrency
    if getattr(args, "max_hosts", None) is not None:
        cfg.max_hosts = args.max_hosts
    if getattr(args, "deep_cert_limit", None) is not None:
        cfg.deep_cert_limit = args.deep_cert_limit
    return cfg


async def _run_scan_with_progress(args) -> int:
    from .pipeline import run_scan

    last_module = ""

    def on_progress(module: str, status: str, message: str) -> None:
        nonlocal last_module
        if status == "running" and module != last_module:
            print(f"  [*] {module} ...", flush=True)
            last_module = module
        elif status == "done":
            print(f"  [+] {module} done", flush=True)
        elif status == "failed":
            print(f"  [!] {module} failed: {message}", flush=True)

    scan_id = await run_scan(
        args.target, args.org, None if args.modules in (None, "all") else args.modules.split(","),
        cfg=get_config(), on_progress=on_progress, wordlist=args.wordlist)
    if args.report:
        from .report_module import write_reports
        written = write_reports(scan_id, ["html", "md", "stix"])
        for p in written:
            print(f"  report: {p}")
    return scan_id


def cmd_scan(args) -> None:
    setup_logging(args.verbose)
    cfg = _cfg_from_args(args, get_config())
    set_config(cfg)
    if not cfg.accept_risk:
        sys.exit(
            "Authorized testing required."
            "\n"
            "You must own the target or have explicit written permission. "
            "Re-run with --authorized / OASIP_AUTHORIZED=1.")
    print(f"OASIP {__version__} - scanning {args.target}"
          + (f" (org: {args.org})" if args.org else ""))
    scan_id = asyncio.run(_run_scan_with_progress(args))
    scan = repos.get_scan(scan_id)
    print(f"\nScan #{scan_id} finished: {scan.status} overall_score={scan.overall_score}")
    s = scan.summary or {}
    print(f"  hosts={s.get('hosts')} ips={s.get('ips')} findings={s.get('findings')} "
          f"takeovers={s.get('takeovers')}")


def cmd_dashboard(args) -> None:
    setup_logging(True)
    get_config()
    import uvicorn
    if args.open:
        import threading
        import time
        import urllib.request
        import webbrowser

        def _open_browser() -> None:
            for _ in range(80):
                try:
                    urllib.request.urlopen(f"http://{args.host}:{args.port}/api/scans", timeout=1)
                    break
                except Exception:
                    time.sleep(0.5)
            webbrowser.open(f"http://{args.host}:{args.port}")

        threading.Thread(target=_open_browser, daemon=True).start()
    print(f"OASIP dashboard starting on http://{args.host}:{args.port}")
    uvicorn.run("oasip.web.app:app", host=args.host, port=args.port, log_level="warning")


def cmd_report(args) -> None:
    from .report_module import write_reports

    scan_id = args.scan_id
    if scan_id is None:
        scans = repos.list_scans(1)
        if not scans:
            sys.exit("no scans found - run 'oasip scan' first")
        scan_id = scans[0]["id"]
    formats = (args.format or "html,md,stix").split(",")
    written = write_reports(scan_id, formats, Path(args.out) if args.out else None)
    for p in written:
        print(p)


def cmd_scans(args) -> None:
    for s in repos.list_scans(50):
        print(f"#{s['id']:>4}  {s['target']:<32} {s['status']:<9} "
              f"score={s['overall_score'] if s['overall_score'] is not None else '-':<5} "
              f"started={s['started_at']}")


def cmd_ct_stream(args) -> None:
    from .services.ctstream import monitor
    from .util import log

    setup_logging(True)
    out_path = get_config().data_dir / "ct_events.jsonl"

    async def on_event(ev: dict) -> None:
        print(json.dumps(ev, sort_keys=True), flush=True)
        with open(out_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(ev, sort_keys=True) + "\n")

    asyncio.run(monitor(args.domain, on_event, args.interval))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="oasip", description="OSINT & Attack Surface Intelligence Platform")
    p.add_argument("--version", action="version", version=f"oasip {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="run a recon scan")
    s.add_argument("target", help="root domain or organization scope")
    s.add_argument("--org", help="organization name (sharpens code/identity/breach modules)")
    s.add_argument("--modules", default="all",
                   help="comma separated: dns,ct,code,identity,breach,fingerprint,correlate,risk (or all)")
    s.add_argument("--wordlist", help="custom subdomain wordlist file")
    s.add_argument("--concurrency", type=int, default=None)
    s.add_argument("--max-hosts", type=int, default=None)
    s.add_argument("--deep-cert-limit", type=int, default=None)
    s.add_argument("--smtp-probe", action="store_true",
                   help="enable guarded RCPT TO email validation (off by default; no mail is sent)")
    s.add_argument("--authorized", action="store_true",
                   help="confirm you own or are explicitly authorized to test this target")
    s.add_argument("--report", action="store_true", help="generate html/md/stix reports on completion")
    s.add_argument("--verbose", action="store_true")
    s.set_defaults(func=cmd_scan)

    d = sub.add_parser("dashboard", help="start the FastAPI + React dashboard")
    d.add_argument("--host", default="127.0.0.1")
    d.add_argument("--port", type=int, default=8123)
    d.add_argument("--open", action="store_true",
                   help="open the dashboard in the default browser once it is ready")
    d.set_defaults(func=cmd_dashboard)

    r = sub.add_parser("report", help="export reports for a scan (html/md/stix)")
    r.add_argument("scan_id", nargs="?", type=int, default=None, help="scan id (defaults to latest)")
    r.add_argument("--format", default="html,md,stix")
    r.add_argument("-o", "--out", help="output directory")
    r.set_defaults(func=cmd_report)

    sc = sub.add_parser("scans", help="list previous scans")
    sc.set_defaults(func=cmd_scans)

    c = sub.add_parser("ct-stream", help="stream new certificates from CT logs (RFC 6962)")
    c.add_argument("domain")
    c.add_argument("--interval", type=int, default=None)
    c.set_defaults(func=cmd_ct_stream)

    i = sub.add_parser("init-db", help="create/upgrade the SQLite/PostgreSQL schema")
    i.set_defaults(func=lambda a: init_db() or print("database ready"))
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
