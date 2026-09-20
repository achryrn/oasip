# OASIP: OSINT and Attack Surface Intelligence Platform

I built OASIP as a fully automated, passive and semi-passive tool for mapping
the external attack surface of a domain or organization. Point it at a target
and it discovers subdomains, IPs, ASNs, certificates, exposed services,
credentials leaked in breaches and public repositories, employee identities,
and running technologies. The collected evidence is then correlated, scored,
and exported as a report, in the spirit of a red-team reconnaissance phase.

OASIP never sends exploit code. Every query is a lookup of information the
target has already exposed publicly.

> **Authorized use only.** Scan only targets you own or have explicit written
> permission to test. OASIP refuses to run without an authorization flag.

## Quick start

```bash
python -m venv .venv
.venv/Scripts/activate            # Windows    (source .venv/bin/activate on macOS/Linux)
pip install -r requirements.txt

cp .env.example .env              # optional: add API keys you hold
oasip init-db
oasip scan example.com --org "Example Corp" --authorized --modules dns,ct,fingerprint
oasip dashboard                   # opens http://127.0.0.1:8123
oasip report --latest             # html + md + stix2 exports in reports/
```

The platform degrades gracefully without API keys: modules 1 (crt.sh and DNS)
and 6 (direct probing, RDAP, NVD) run with no configuration, and every key
added to `.env` unlocks additional sources. The default database is a
zero-setup SQLite file; set `OASIP_DATABASE_URL` to a PostgreSQL URL for the
full database stack.

### Windows: double-click launch

For the most common workflows, no terminal is required. I ship three launchers
in the project root:

| File | Purpose |
|------|---------|
| `OASIP - Setup.bat` | One-time environment creation (requires Python 3.11 or newer). Run it first, or let another launcher trigger it automatically. |
| `OASIP - Dashboard.bat` | Starts the dashboard at http://127.0.0.1:8123 and opens it in your browser. |
| `OASIP - New Scan.bat` | Prompts for a target domain (and an optional organization name), requires an explicit YES authorization confirmation, runs a full scan with report export, and opens the `reports\` folder. |

On first run the launchers create `.venv\` and install `requirements.txt`
automatically. API keys remain optional; edit `.env` (copy of
`.env.example`) to add sources you hold credentials for.

## Modules

| # | Module | Sources (free tier) | Notes |
|---|--------|--------------------|-------|
| 1 | DNS and Subdomain Enumeration | crt.sh, SecurityTrails, VirusTotal, HackerTarget, own wordlist resolver | SPF/DMARC/DKIM posture, wildcard detection, one-shot AXFR check |
| 2 | Certificate Transparency Mining | crt.sh + RFC 6962 logs (Google and Cloudflare) | weakness flags (expired, short RSA, SHA-1), reuse and wildcard detection, org-field mining, real-time `ct-stream` |
| 3 | Code Repository Scanner | GitHub Search API, TruffleHog (git history) | 17 target-scoped queries, secret classification, internal-hostname discovery |
| 4 | Breach Intelligence | Have I Been Pwned, IntelX (+ DeHashed/LeakCheck stubs) | plaintext/hashed/none classification, recency weighting, paste mirrors |
| 5 | Identity and Employee Mapping | GitHub org members, commit emails | format inference, permutation engine, opt-in guarded RCPT TO validation, LinkedIn dork generation (no scraping) |
| 6 | Infra and Tech Fingerprinting | Shodan, Censys, BinaryEdge, RDAP, direct HTTP/TLS probes | Wappalyzer-lite signatures, banner and header capture, version-to-NVD CVE mapping |
| 7 | Asset Correlation | local graph | vhost/ASN/cert/server clustering, shadow IT, dangling DNS, subdomain-takeover fingerprints (20 providers) |
| 8 | Risk Scoring | local graph | documented 0 to 100 factor table, finding-weighted aggregate |
| 9 | Dashboard and Report | FastAPI + React/Recharts, Jinja2 | self-contained HTML, Markdown, STIX 2.1 JSON |

### Module 1 detail

* Passive DNS from SecurityTrails / VirusTotal / HackerTarget (key-gated).
* CT SAN mining from crt.sh (unlimited, keyless) with one level of recursive
  expansion.
* Wordlist brute force against `wordlists/default_subdomains.txt` (or SecLists
  via `--wordlist`) through a rotating resolver pool with a shared rate limit
  and wildcard-DNS detection.
* Per-host record extraction: A, AAAA, CNAME, MX, TXT, NS, SOA, PTR.
* SPF: ip4/ip6 ranges, `include:` third-party senders, and policy (permissive
  `+all` or missing policy flagged). DMARC: `p=` policy, permissive (none or
  missing) flagged. DKIM: 32 common selectors checked.
* A single AXFR query against the first usable NS. This is a plain DNS query;
  if the administrator left transfers open, that itself is a finding.

### Module 2 detail

Each crt.sh row is reduced to a stable identity fingerprint (serial, issuer,
dates, SANs), so crt.sh metadata and live TLS captures converge on the same
certificate record. A bounded deep pass fetches the actual certificate and
flags: expired or expiring within 30 days, RSA below 2048 bits, SHA-1 or MD5
signatures, self-signed, and wildcard. Certificate reuse (the same identity
across many hostnames) is detected automatically.

`oasip ct-stream example.com` runs the RFC 6962 monitor continuously. On
first run it snapshots each public log's tail; afterwards it emits every new
certificate matching your domain as it is logged (per-log tree-size state lives
in `data/ct_state_*.json`).

### Module 3 detail

The module runs the documented GitHub search query set: org-anchored `.env`,
password, and api_key queries, plus domain-anchored `smtp`, `jdbc`,
`BEGIN RSA PRIVATE KEY`, internal-hostname, and internal-IP-range dorks.
Code search requires a `GITHUB_TOKEN`. Matched files are fetched raw and
classified for AWS keys, GitHub tokens, Slack/Stripe/Google/SendGrid keys, PEM
private keys, connection strings, high-entropy generic secrets, and extracted
emails and internal hostnames. If the `trufflehog` binary is installed, the
module also scans the organization's public repository git history, so secrets
deleted from the working tree but still present in history are found.

### Module 5 and guardrails

GitHub organization member enumeration and commit-author emails build the
employee table. `infer_email_format` learns the organization's convention
from observed addresses, and a permutation engine generates `first.last`,
`flast`, `f.last`, and similar candidates for every employee.

RCPT TO validation is off by default. Enable it only with `--smtp-probe` (or
the environment setting), and only against mail servers you are authorized to
probe. Guardrails: sequential probes, at least 4 seconds between probes, at
most 40 candidates, no `DATA` command, and a placeholder sender. LinkedIn
enumeration is emitted as search queries (dorks) only, never scraped, in
respect of the platform's terms of service.

### Module 6 detail

For every unique public IP the module queries Shodan (100 credits per month),
Censys (250 per month), BinaryEdge, and RDAP, and merges the results into
ports, banners, ASN, organization, and cloud provider. TLS version evidence is
collected and TLS 1.0/1.1 are flagged. For every hostname it performs one HTTP
GET (headers and body fed to the Wappalyzer-lite fingerprint engine) and one
TLS handshake (leaf certificate capture feeding expiry and self-signed flags).
Detected product/version combinations are looked up in NVD and the highest
CVSS score is attached to the asset with a correlated finding.

### Module 7 detail

* vhost mapping (IP to hostnames), ASN grouping, certificate grouping, and
  server fingerprint grouping.
* Shadow IT: corporate-named subdomains on consumer cloud ASNs, and CNAMEs
  into unmanaged hosting providers.
* Subdomain takeover: probed CNAME chains, provider error-page fingerprints
  (GitHub Pages, Heroku, Netlify, Vercel, S3, Azure Blob, Shopify, Zendesk,
  Fastly, and others), and NXDOMAIN-with-CNAME dangling detection.

### Module 8: scoring table

| Factor | Max points |
|---|---|
| Critical CVE on detected version | 25 |
| Credential exposure in breach (plaintext) | 20 |
| Secret exposed in public repository | 20 |
| Expired or expiring SSL certificate | 10 |
| Missing or permissive DMARC | 8 |
| Subdomain takeover vulnerable | 15 |
| Exposed admin panel | 10 |
| TLS 1.0 or 1.1 enabled | 7 |
| Self-signed certificate | 5 |
| Weak SSH key (RSA below 2048 bits) | 5 |
| Dangling DNS record | 10 |
| Asset on unexpected infrastructure | 5 |

Each asset receives a score from 0 to 100 (factors are capped at 100). The
overall target score is a finding-weighted aggregate across assets, bucketed
into low, medium, high, and critical tiers.

### Module 9

* Dashboard: a FastAPI JSON API plus a single-page React (UMD) app with
  Recharts served at `/`. It shows KPI cards, a risk heatmap, an asset
  inventory with score badges, breach summaries, repository findings, a CVE
  list sorted by CVSS, a certificate timeline, takeover and shadow tables, and
  people and email candidates. The view refreshes while a scan runs; new scans
  are submitted through `POST /api/scan`.
* Reports: fully self-contained HTML (inline CSS, no external dependencies),
  Markdown, and a STIX 2.1 JSON bundle (identity, domain-name, ipv4-addr,
  vulnerability, observed-data, indicator, and relationship objects) for import
  into threat-intelligence platforms.

## Configuration

All settings come from the environment or `.env` (see `.env.example`): API
keys for Shodan, Censys, BinaryEdge, VirusTotal, SecurityTrails, HackerTarget,
GitHub, HIBP, IntelX, DeHashed, and LeakCheck, plus `OASIP_DATABASE_URL`,
`OASIP_CONCURRENCY`, `OASIP_MAX_HOSTS`, `OASIP_DEEP_CERT_LIMIT`,
`OASIP_SMTP_PROBE`, `OASIP_AUTHORIZED`, and others.

## Architecture

```
[Target input] -> [Orchestration pipeline (asyncio, per-service rate limits)]
   |- dns          crt.sh SANs + passive DNS + wordlist + records/policy/AXFR
   |- ct           certificate analytics + RFC 6962 stream
   |- code         GitHub search + TruffleHog (new hosts enrich)
   |- identity     org members, commit emails, permutations, opt-in SMTP probe
   |- breach       HIBP + IntelX classification
   |- fingerprint  scan-data services + HTTP/TLS probes + Wappalyzer + NVD
   |- correlate    relationships, shadow IT, takeover fingerprints
   `- risk         0 to 100 factor scores, weighted aggregate
        |
        v
   [SQLite/PostgreSQL] -> [FastAPI + React/Recharts dashboard]
        |
        v
   [HTML/Markdown/STIX 2.1 report exporter]
```

I built the pipeline as a plain `asyncio` DAG; it requires no external
infrastructure. For distributed deployments, `oasip/celery_app.py` exposes
the same scan as a Celery task, and any PostgreSQL URL is supported through
SQLAlchemy.

## Development

```bash
pip install -r requirements-dev.txt
pytest -q
```

I keep the suite green with pytest; the tests exercise the parsers, the
certificate utilities, the CT-stream leaf decoder, the risk engine, and a full
report round-trip.

## Ethics and operational notes

* Every outbound request is rate-limited and low-volume; resolver pools rotate
  public DNS servers under shared throttles (semi-passive DNS).
* AXFR is a single standard DNS query; takeover checks are HTTP GET requests
  against hostnames you resolved for a target you are authorized to test.
* Email RCPT probing is off by default and is a permission-sensitive technique.
  Keep it disabled unless the engagement explicitly covers it.
* The dashboard's React app is loaded from CDNs to stay dependency-light. For
  air-gapped use, vendor the UMD bundles into `oasip/web/static/`.

<!-- last-verified: 2026-09-20 02:58 UTC -->
