"""ScanContext shared by modules (kept separate to avoid import cycles)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from ..config import Config


@dataclass
class ScanContext:
    scan_id: int
    target: str
    org_name: Optional[str]
    cfg: Config
    extra_hosts: List[str] = field(default_factory=list)

    def add_hosts(self, hosts: List[str], source: str = "") -> None:
        for h in hosts:
            if h not in self.extra_hosts:
                self.extra_hosts.append(h)
