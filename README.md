# OASIP — OSINT & Attack Surface Intelligence Platform

A fully automated, passive / semi-passive external attack-surface mapper. Point
it at a domain or organization name and it discovers subdomains, IPs, ASNs,
certificates, exposed services, leaked credentials in breaches and public
repositories, employee identities, and running technologies — then correlates,
scores, and reports the surface exactly like a red-team recon phase. **No
exploit code is ever sent; every query is a lookup the target already exposed
publicly.**

> ⚠️ **Authorized use only.** Scan targets you own or have explicit written
> permission to test. OASIP refuses to run without an authorization flag.

## Quick start

```bash
python -m venv .venv
.venv/Scripts/activate            # Windows    (source .venv/bin/activate on macOS/Linux)
pip install -r requirements.txt

cp .env.example .env              # optional: add API keys you hold
oasip init-db
oasip scan example.com --org "Example Corp" --authorized --modules dns,ct,fingerprint
oasip dashboard --port 8000       # open http://127.0.0.1:8000
oasip report --latest             # html + md + stix2 exports in reports/
```

Everything degrades gracefully: with zero API keys OASIP still runs module 1
(crt.sh, DNS) and module 6 (direct probing, RDAP, NVD); each key you add in
`.env` unlocks more sources. Configure a PostgreSQL URL with
`OASIP_DATABASE_URL` for the full database stack — the default is a
zero-setup SQLite file.

### Windows: double-click launch

No terminal needed for the common paths — three launchers live in the project root:

| File | What it does |
|------|--------------|
| `OASIP - Setup.bat` | One-time environment creation (needs Python 3.11+ installed). Run it first, or let another launcher trigger it automatically. |
| `OASIP - Dashboard.bat` | Starts the dashboard at http://127.0.0.1:8123 and opens it in your browser. |
| `OASIP - New Scan.bat` | Prompts for a target domain (+ optional org), requires an explicit *YES* authorization confirmation, runs a full scan with report export, then opens the `reports\` folder. |

The launchers create `.venv\` and install `requirements.txt` automatically on
first run. API keys are optional — edit `.env` (copy of `.env.example`) to add
sources you hold credentials for.

## Modules

| # | Module | Sources (free tier) | Notes |
|---|--------|--------------------|-------|
| 1 | DNS & Subdomain Enumeration | crt.sh, SecurityTrails, VirusTotal, HackerTarget, own wordlist resolver | SPF/DMARC/DKIM posture, wildcard detection, one-shot AXFR check |
| 2 | Certificate Transparency Mining | crt.sh + RFC 6962 logs (Google/Cloudflare) | weakness flags (expired, short RSA, SHA-1), reuse & wildcard detection, org-field mining, real-time `ct-stream` |
| 3 | Code Repository Scanner | GitHub Search API, TruffleHog (git history) | 17 target-scoped queries, secret classification, internal-hostname discovery |
| 4 | Breach Intelligence | Have I Been Pwned, IntelX (+ DeHashed/LeakCheck stubs) | plaintext/hashed/none classification, recency weighting, paste mirrors |
| 5 | Identity & Employee Mapping | GitHub org members, commit emails | format inference, permutation engine, opt-in guarded RCPT TO validation, LinkedIn dork generation (no scraping) |
| 6 | Infra & Tech Fingerprinting | Shodan, Censys, BinaryEdge, RDAP, direct HTTP/TLS probes | Wappalyzer-lite signatures, banner & header capture, version→NVD CVE mapping |
| 7 | Asset Correlation | local graph | vhost/ASN/cert/server clustering, shadow-IT, dangling DNS, subdomain-takeover fingerprints (20 providers) |
| 8 | Risk Scoring | local graph | documented 0–100 factor table, finding-weighted aggregate |
| 9 | Dashboard & Report | FastAPI + React/Recharts, Jinja2 | self-contained HTML, Markdown, STIX 2.1 JSON |

### Module 1 detail

* Passive DNS from SecurityTrails / VirusTotal / HackerTarget (key-gated).
* **CT SAN mining** from crt.sh (unlimited, keyless) with one level of
  recursive expansion.
* **Brute force** against your wordlist (`wordlists/default_subdomains.txt`,
  or SecLists via `--wordlist`) through a rotating resolver pool with a
  shared rate limit and wildcard-DNS detection.
* Per-host record extraction: A, AAAA, CNAME, MX, TXT, NS, SOA, PTR.
* SPF: ip4/ip6 ranges + `include:` third-party senders + policy
  (permissive `+all`/missing flagged). DMARC: `p=` policy, permissive
  (none/missing) flagged. DKIM: 32 common selectors checked.
* Single **AXFR query** against the first usable NS (a plain DNS query; if the
  admin left transfers open that is itself a finding).

### Module 2 detail

Each crt.sh row is reduced to a stable *identity fingerprint*
(serial|issuer|dates|SANs) so crt.sh metadata and live TLS captures converge
on the same certificate record. A bounded deep pass fetches the actual
certificate and flags: expired / expiring ≤30 d, RSA < 2048, SHA-1/MD5
signatures, self-signed, wildcard. Certificate reuse (same identity across
many hostnames) is detected automatically.

`oasip ct-stream example.com` runs the RFC 6962 monitor forever: it snapshots
each public log's tail on first run, then emits **every new certificate
matching your domain as it is logged** (per-log tree-size state in
`data/ct_state_*.json`).

### Module 3 detail

Runs the documented GitHub search query set (org-anchored `.env`/password/
api_key/... plus domain-anchored `smtp`, `jdbc`, `BEGIN RSA PRIVATE KEY`,
internal-hostname and internal-IP-range dorks — code *search requires* a
`GITHUB_TOKEN`). Matched files are fetched raw and classified: AWS keys,
GitHub tokens, Slack/Stripe/Google/SendGrid keys, PEM private keys, connection
strings, high-entropy generic secrets, plus email and internal-hostname
extraction. If the `trufflehog` binary is installed it also scans the org's
public repository **git history** — secrets deleted from the working tree but
present in history are found.

### Module 5 & guardrails

GitHub org member enumeration and commit-author emails build the employee
table; `infer_email_format` learns the org convention from observed
addresses and a permutation engine generates `first.last`, `flast`,
`f.last`, etc. candidates for every employee.

**RCPT TO validation is off by default** — enable only with
`--smtp-probe`/env, and only against mail servers you are authorized to
probe. Guardrails: sequential probes, ≥4 s between probes, ≤40 candidates,
no `DATA`, placeholder sender. LinkedIn enumeration is emitted as search
queries (dorks) — never scraped, respecting ToS.

### Module 6 detail

For every unique public IP: Shodan (100 credits/mo), Censys (250/mo),
BinaryEdge, RDAP — merged into ports/banners/ASN/org/cloud-provider; TLS
version evidence (TLS 1.0/1.1 flagged). For every hostname: one HTTP GET
(headers + body → Wappalyzer-lite fingerprints) and one TLS handshake (leaf
cert capture → expiry/self-signed flags). Detected `product version`
combinations are looked up in NVD and the highest CVSS is attached to the
asset with a correlated finding.

### Module 7 detail

* vhost mapping (IP → hostnames), ASN grouping, certificate grouping, server
  fingerprint grouping.
* Shadow IT: corporate-named subdomains on consumer cloud ASNs, CNAMEs into
  unmanaged hosting providers.
* Subdomain takeover: CNAME chains probed, provider error-page fingerprints
  (GitHub Pages, Heroku, Netlify, Vercel, S3, Azure Blob, Shopify, Zendesk,
  Fastly, …), and NXDOMAIN-with-CNAME dangling detection.

### Module 8 — scoring table

| Factor | Max pts |
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
| Weak SSH key (< 2048 bit RSA) | 5 |
| Dangling DNS record | 10 |
| Asset on unexpected infrastructure | 5 |

Each asset gets a 0–100 score (factors capped at 100); the **overall target
score** is a finding-weighted aggregate across assets, bucketed into
low/medium/high/critical tiers.

### Module 9

* **Dashboard:** FastAPI JSON API + single-page React (UMD) + Recharts CDN
  app served at `/` — KPI cards, risk heatmap, asset inventory with score
  badges, breach summary, repository findings, CVE list sorted by CVSS,
  certificate timeline, takeover/shadow tables, people & email candidates.
  Live-refreshes while a scan runs via `POST /api/scan`.
* **Reports:** fully self-contained HTML (inline CSS, no external deps),
  Markdown, and a **STIX 2.1** JSON bundle (identity, domain-name, ipv4-addr,
  vulnerability, observed-data, indicator, relationships) for import into
  threat-intel platforms.

## Configuration

All settings via environment / `.env` (see `.env.example`): API keys for
Shodan, Censys, BinaryEdge, VirusTotal, SecurityTrails, HackerTarget, GitHub,
HIBP, IntelX, DeHashed, LeakCheck; `OASIP_DATABASE_URL`,
`OASIP_CONCURRENCY`, `OASIP_MAX_HOSTS`, `OASIP_DEEP_CERT_LIMIT`,
`OASIP_SMTP_PROBE`, `OASIP_AUTHORIZED`, …

## Architecture

```
[Target input] → [Orchestration pipeline (asyncio, per-service rate limits)]
   ├─ dns          crt.sh SANs + passive DNS + wordlist + records/policy/AXFR
   ├─ ct           certificate analytics + RFC 6962 stream
   ├─ code         GitHub search + TruffleHog → (new hosts enrich)
   ├─ identity     org members, commit emails, permutations, opt-in SMTP probe
   ├─ breach       HIBP + IntelX classification
   ├─ fingerprint  scan-data services + HTTP/TLS probes + Wappalyzer + NVD
   ├─ correlate    relationships, shadow IT, takeover fingerprints
   └─ risk         0–100 factor scores, weighted aggregate
        ↓
  [SQLite/PostgreSQL] → [FastAPI + React/Recharts dashboard]
        ↓
  [HTML/Markdown/STIX 2.1 report exporter]
```

The pipeline is a plain `asyncio` DAG (no infra required). For distributed
deployments, `oasip/celery_app.py` exposes the same scan as a Celery task
and any PostgreSQL URL is supported via SQLAlchemy.

## Development

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Ethics & operational notes

* Every outbound request is rate-limited and low-volume; resolver pools
  rotate public DNS servers with shared throttles (semi-passive DNS).
* AXFR is a single standard DNS query; takeover checks are HTTP GETs against
  hostnames *you* resolved for a target you are authorized to test.
* Email RCPT probing is off by default and is a permission-sensitive
  technique — keep it disabled unless the engagement explicitly covers it.
* The dashboard's React app is loaded from CDNs to stay dependency-light;
  for air-gapped use, vendor the UMD bundles into `oasip/web/static/`.
