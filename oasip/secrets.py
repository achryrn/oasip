"""Secret detection: regex patterns, connection-string parsing and
entropy-based generic key detection."""
from __future__ import annotations

import math
import re
from typing import Dict, List, Optional

PATTERNS: List[Dict] = [
    {"type": "AWS Access Key", "sev": "critical",
     "re": re.compile(r"AKIA[0-9A-Z]{16}")},
    {"type": "AWS Secret Key", "sev": "critical",
     "re": re.compile(r"(?i)(aws|amazon)[_-]?(secret|access)[_-]?key\s*[=:]\s*[\'\"]?([A-Za-z0-9/+=]{40})")},
    {"type": "GitHub Token", "sev": "critical",
     "re": re.compile(r"ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}")},
    {"type": "Slack Token", "sev": "critical",
     "re": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")},
    {"type": "Stripe Key", "sev": "critical",
     "re": re.compile(r"sk_live_[0-9A-Za-z]{20,}")},
    {"type": "Google API Key", "sev": "high",
     "re": re.compile(r"AIza[0-9A-Za-z_-]{35}")},
    {"type": "Twilio API Key", "sev": "high",
     "re": re.compile(r"SK[0-9a-fA-F]{32}")},
    {"type": "SendGrid Key", "sev": "high",
     "re": re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}")},
    {"type": "Private Key", "sev": "critical",
     "re": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")},
    {"type": "JWT/API Token", "sev": "high",
     "re": re.compile(r"(?i)(api[_-]?key|auth[_-]?token|bearer|access[_-]?token)\s*[=:]\s*[\'\"]?(eyJ[A-Za-z0-9_.-]{20,}|[A-Za-z0-9_\-]{30,})")},
    {"type": "Database Connection String", "sev": "high",
     "re": re.compile(r"(?i)(mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|prestodb)(://)([^\s'\"]+)")},
    {"type": "SMTP Credentials", "sev": "high",
     "re": re.compile(r"(?i)(smtp|mail)\.[a-z0-9.\-]+\.[a-z]{2,}:[0-9]+(?:,[^\s'\"]{4,})?")},
]

_GENERIC_KEY_RE = re.compile(
    r"(?i)(?<![a-z0-9])((?:api|app|client|secret|pass|pwd|token|key|auth)[_-]?(?:key|secret|token|password|pass|pwd)?)\s*[=:]\s*[\'\"]?([A-Za-z0-9_\-./+]{12,64})[\'\"]?",
)


def shannon(s: str) -> float:
    if not s:
        return 0.0
    freqs = {}
    for ch in s:
        freqs[ch] = freqs.get(ch, 0) + 1
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in freqs.values())


def classify(text: str) -> List[Dict]:
    """All identifiable secrets in a chunk of text."""
    out: List[Dict] = []
    for pat in PATTERNS:
        for m in pat["re"].finditer(text):
            out.append({
                "type": pat["type"],
                "severity": pat["sev"],
                "match": m.group(0)[:200],
                "context": text[max(0, m.start() - 60):m.end() + 60],
            })
    # generic high-entropy keys next to key-like variable names
    for m in _GENERIC_KEY_RE.finditer(text):
        value = m.group(2)
        if len(value) >= 14 and shannon(value) > 3.4:
            out.append({
                "type": "Generic Secret (" + m.group(1).lower() + ")",
                "severity": "medium",
                "match": value,
                "context": text[max(0, m.start() - 60):m.end() + 60],
            })
    return out


def extract_internal_hostnames(text: str, domain: str) -> List[str]:
    """Hostnames mentioned in code (new discovery candidates).

    Keeps names clearly related to the target (subdomains, shared apex label,
    or 3+ labels that do not end in a well-known public TLD).
    """
    public_tlds = {"com", "org", "net", "edu", "gov", "io", "co", "uk", "de",
                   "fr", "jp", "au", "ca", "cn", "ru", "br", "in", "me", "tv"}
    out = []
    apex = domain.split(".")[-1]
    for m in re.finditer(r"(?i)(?:https?://)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}", text):
        h = m.group(0).strip().lower().split("://")[-1]
        h = h.split("/")[0].split(":")[0]
        if " " in h or h.startswith("www.") or "." not in h:
            continue
        labels = h.split(".")
        if h == domain or h.endswith("." + domain):
            out.append(h)
        elif len(labels) >= 3 and (labels[-1] == apex or labels[-1] not in public_tlds):
            out.append(h)
    return list(dict.fromkeys(out))


def extract_conn_string_targets(text: str) -> List[str]:
    out = []
    for m in re.finditer(r"(?i)(mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp)://([^\s'\"]+)", text):
        val = m.group(2)
        host = val.split("@")[-1].split("/")[0].split(":")[0]
        if host and not host.startswith(("127.", "10.", "192.168", "localhost", "0.0.0.0", "::1")):
            out.append(host)
    return list(dict.fromkeys(out))
