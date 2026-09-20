"""A compact, dependency-free port of Wappalyzer-style fingerprinting.

Matches HTTP response headers, cookies, and HTML content against curated
signatures and extracts version strings (group 1 of each regex). Signal
quality matters more than breadth here: the set covers the technologies that
drive the highest-value findings (WAF, CMS, frameworks, PaaS, analytics).
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

# name -> list of dict(field, name?, pattern, version?, category, confidence?)
SIGNATURES: Dict[str, List[Dict]] = {
    # --- CDN / WAF / proxies -------------------------------------------
    "Cloudflare": [
        {"field": "headers", "name": "server", "pattern": r"cloudflare"},
        {"field": "headers", "name": "cf-ray", "pattern": r".+"},
        {"field": "headers", "name": "cf-cache-status", "pattern": r".+"},
        {"field": "cookies", "name": "__cf_bm", "pattern": r".+"},
        {"field": "headers", "name": "cf-connecting-ip", "pattern": r".+"},
    ],
    "Akamai": [
        {"field": "headers", "name": "server", "pattern": r"akamai"},
        {"field": "headers", "name": "x-akamai-transformed", "pattern": r".+"},
        {"field": "headers", "name": "x-akamai-request-id", "pattern": r".+"},
    ],
    "Fastly": [
        {"field": "headers", "name": "x-served-by", "pattern": r"(fastly|cache-)"},
        {"field": "headers", "name": "x-fastly-request-id", "pattern": r".+"},
        {"field": "headers", "name": "fastly-debug-digest", "pattern": r".+"},
    ],
    "Amazon S3": [
        {"field": "headers", "name": "server", "pattern": r"AmazonS3"},
        {"field": "headers", "name": "x-amz-bucket-region", "pattern": r".+"},
        {"field": "html", "name": None, "pattern": r"<ListBucketResult"},
    ],
    "Amazon CloudFront": [
        {"field": "headers", "name": "x-amz-cf-id", "pattern": r".+"},
        {"field": "headers", "name": "x-amz-cf-pop", "pattern": r".+"},
        {"field": "headers", "name": "via", "pattern": r"cloudfront"},
    ],
    "Google Cloud Storage": [
        {"field": "headers", "name": "server", "pattern": r"UploadServer|GCS"},
    ],
    "Azure Front Door": [
        {"field": "headers", "name": "x-azure-ref", "pattern": r".+"},
    ],
    "Varnish": [{"field": "headers", "name": "via", "pattern": r"(?:^|,)\s*varnish(?:\/([\d.]+))?"}],
    "HAProxy": [{"field": "headers", "name": "server", "pattern": r"HAProxy(?:\s*([\d.]+))?"}],
    "Imperva Incapsula": [{"field": "cookies", "name": "visid_incap", "pattern": r".+"}],
    "AWS WAF": [{"field": "headers", "name": "x-amzn-waf-action", "pattern": r".+"}],
    # --- Web servers ------------------------------------------------------
    "Nginx": [{"field": "headers", "name": "server", "pattern": r"(?:^|[\s/])nginx(?:/([\d.]+))?"}],
    "Apache HTTP Server": [{"field": "headers", "name": "server", "pattern": r"Apache(?:/([\d.]+))?"}],
    "Microsoft IIS": [{"field": "headers", "name": "server", "pattern": r"Microsoft-IIS(?:/([\d.]+))?"}],
    "LiteSpeed": [{"field": "headers", "name": "server", "pattern": r"LiteSpeed(?:/([\d.]+))?"}],
    "OpenResty": [{"field": "headers", "name": "server", "pattern": r"openresty(?:/([\d.]+))?"}],
    "Caddy": [{"field": "headers", "name": "server", "pattern": r"Caddy(?:/([\d.]+))?"}],
    "Traefik": [{"field": "headers", "name": "server", "pattern": r"Traefik(?:/([\d.]+))?"}],
    "Cowboy": [{"field": "headers", "name": "server", "pattern": r"Cowboy(?:/([\d.]+))?"}],
    "Gunicorn": [{"field": "headers", "name": "server", "pattern": r"gunicorn(?:/([\d.]+))?"}],
    "Envoy": [{"field": "headers", "name": "server", "pattern": r"envoy(?:/([\d.]+))?"}],
    # --- CMS --------------------------------------------------------------
    "WordPress": [
        {"field": "html", "name": None, "pattern": r"wp-content(?:/plugins|/themes)?"},
        {"field": "cookies", "name": "wordpress_", "pattern": r".+"},
        {"field": "html", "name": None, "pattern": r'<meta name="generator" content="WordPress\s*([\d.]+)'},
        {"field": "headers", "name": "x-pingback", "pattern": r"/xmlrpc\.php$"},
    ],
    "Drupal": [
        {"field": "html", "name": None, "pattern": r"drupal-settings-json|sites/default/files"},
        {"field": "headers", "name": "x-generator", "pattern": r"Drupal\s*([\d.]+)"},
    ],
    "Joomla": [
        {"field": "html", "name": None, "pattern": r"/media/system/js/"},
        {"field": "html", "name": None, "pattern": r'<meta name="generator" content="Joomla!'},
    ],
    "Magento": [
        {"field": "html", "name": None, "pattern": r"skin/frontend/|mage\?"},
        {"field": "cookies", "name": "frontend", "pattern": r".+"},
    ],
    "Shopify": [
        {"field": "html", "name": None, "pattern": r"cdn\.shopify\.com|Shopify\.theme"},
        {"field": "headers", "name": "x-shopid", "pattern": r".+"},
    ],
    "Ghost": [{"field": "html", "name": None, "pattern": r'<link rel="canonical"[^>]+/ghost/'}],
    "Hugo": [{"field": "html", "name": None, "pattern": r'<meta name="generator" content="Hugo\s*([\d.]+)'}],
    "DokuWiki": [{"field": "html", "name": None, "pattern": r"dokuwiki\s*/\s*dokuwiki"}],
    # --- Frameworks / runtimes -------------------------------------------
    "PHP": [
        {"field": "headers", "name": "x-powered-by", "pattern": r"PHP(?:/([\d.]+))?"},
        {"field": "html", "name": None, "pattern": r'<input[^>]+name="PHPSESSID|PHPSESSID='},
    ],
    "ASP.NET": [
        {"field": "headers", "name": "x-aspnet-version", "pattern": r"([\d.]+)"},
        {"field": "headers", "name": "x-powered-by", "pattern": r"ASP\.NET(?:/([\d.]+))?"},
        {"field": "cookies", "name": "ASP.NET_SessionId", "pattern": r".+"},
        {"field": "headers", "name": "x-aspnetmvc-version", "pattern": r"([\d.]+)"},
    ],
    "Express": [
        {"field": "headers", "name": "x-powered-by", "pattern": r"Express(?:/([\d.]+))?"},
        {"field": "headers", "name": "x-express", "pattern": r"([\d.]+)"},
    ],
    "Django": [
        {"field": "html", "name": None, "pattern": r"csrfmiddlewaretoken"},
        {"field": "cookies", "name": "csrftoken", "pattern": r".+"},
        {"field": "headers", "name": "x-frame-options", "pattern": r"^(?:SAMEORIGIN|DENY)$"},
    ],
    "Flask": [{"field": "headers", "name": "server", "pattern": r"Werkzeug(?:/([\d.]+))?"}],
    "FastAPI": [{"field": "html", "name": None, "pattern": r"<title>FastAPI</title>|swagger-ui-dark"}],
    "Ruby on Rails": [
        {"field": "headers", "name": "x-powered-by", "pattern": r"Phusion Passenger"},
        {"field": "headers", "name": "server", "pattern": r"Phusion Passenger(?:\s*([\d.]+))?"},
        {"field": "cookies", "name": "_session", "pattern": r".+"},
    ],
    "Laravel": [{"field": "html", "name": None, "pattern": r'<meta name="csrf-token" content="[A-Za-z0-9+/]{40}='}],
    "Spring": [
        {"field": "headers", "name": "x-application-context", "pattern": r".+"},
        {"field": "html", "name": None, "pattern": r"Whitelabel Error Page"},
    ],
    "Tomcat": [{"field": "headers", "name": "server", "pattern": r"Apache-Coyote/([\d.]+)"}],
    "Jetty": [{"field": "headers", "name": "server", "pattern": r"Jetty\(([\d.]+)"}],
    "Go net/http": [{"field": "headers", "name": "server", "pattern": r"^Go$|Go-http-server"}],
    "Node.js": [{"field": "headers", "name": "x-powered-by", "pattern": r"Node\.js(?:/([\d.]+))?"}],
    # --- Frontend libraries ----------------------------------------------
    "React": [
        {"field": "html", "name": None, "pattern": r"data-reactroot|__NEXT_DATA__|_next/static"},
        {"field": "html", "name": None, "pattern": r"react@?[\d.]*"},
    ],
    "Next.js": [{"field": "html", "name": None, "pattern": r"__NEXT_DATA__|/_next/static/"}],
    "Vue.js": [{"field": "html", "name": None, "pattern": r"data-v-[a-f0-9]{6,}|vue\.runtime|__VUE__"}],
    "Angular": [{"field": "html", "name": None, "pattern": r"ng-version=|ng-app=|angular\.js"}],
    "jQuery": [{"field": "html", "name": None, "pattern": r"jquery[.-]?(?:[\d.]*)[.-]?min\.js|jQuery v([\d.]+)"}],
    "Bootstrap": [{"field": "html", "name": None, "pattern": r"bootstrap(?:[.-])([\d.]+)(?:[.-]min)?\.css"}],
    "Tailwind CSS": [{"field": "html", "name": None, "pattern": r"tailwindcss|tailwind\s*:.*\b(?:@apply|config)\b"}],
    "Font Awesome": [{"field": "html", "name": None, "pattern": r"font-awesome(?:/([\d.]+))?|fa-[a-z0-9-]+"}],
    # --- Analytics ---------------------------------------------------------
    "Google Analytics": [
        {"field": "html", "name": None,
         "pattern": r"google-analytics\.com/analytics\.js|gtag\(\s*['\"']config['\"']\s*,\s*['\"']G-[A-Z0-9]{6,}"},
    ],
    "Matomo": [{"field": "html", "name": None, "pattern": r"piwik\.js|matomo\.js"}],
    "Hotjar": [{"field": "html", "name": None, "pattern": r"static\.hotjar\.com/c/hotjar-"}],
    "New Relic": [{"field": "html", "name": None, "pattern": r"js-agent\.newrelic\.com"}],
    # --- Products / panels --------------------------------------------------
    "phpMyAdmin": [{"field": "html", "name": None, "pattern": r"phpMyAdmin|pma_password"}],
    "Grafana": [{"field": "html", "name": None, "pattern": r"<title>Grafana</title>|grafana-app"}],
    "Jenkins": [{"field": "headers", "name": "x-jenkins", "pattern": r"([\d.]+)"}],
    "GitLab": [{"field": "html", "name": None, "pattern": r"window\.gon\s*=|gitlab-environment|about\?auto_login"}],
    "Kibana": [{"field": "html", "name": None, "pattern": r"<title>Kibana</title>|kbn-injected-metadata|csp-rule-id"}],
    "Prometheus": [{"field": "html", "name": None, "pattern": r"<title>Prometheus Time Series Collection"}],
    "Consul": [{"field": "html", "name": None, "pattern": r"<title>Consul by HashiCorp"}],
    "Vault": [{"field": "html", "name": None, "pattern": r"<title>Vault by HashiCorp"}],
    "Zendesk": [{"field": "html", "name": None, "pattern": r"zendesk|help\.zendesk\.com|zdassets\.com"}],
    "Exim": [{"field": "headers", "name": "server", "pattern": r"Exim\s*([\d.]+)?"}],
    "Postfix": [{"field": "headers", "name": "server", "pattern": r"Postfix"}],
    "OpenSSH": [{"field": "html", "name": None, "pattern": r"OpenSSH_(\d+\.\d+)"}],
}

CATEGORY_DEFAULT = "Unknown"


def fingerprint(headers: Optional[Dict[str, str]], body: Optional[str],
                cookies: Optional[Dict[str, str]] = None) -> List[Dict]:
    """Returns [{name, category, version, confidence, evidence}] sorted by name."""
    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    body = body or ""
    cookies = {str(k).lower(): str(v) for k, v in (cookies or {}).items()}
    found: Dict[str, Dict] = {}
    for name, sigs in SIGNATURES.items():
        best_version, evidence = "", ""
        matched = False
        for sig in sigs:
            field = sig.get("field")
            target = None
            if field == "headers":
                target = headers.get(sig["name"].lower())
            elif field == "cookies":
                target = cookies.get(sig["name"].lower())
            elif field == "html":
                target = body
            if target is None:
                continue
            try:
                m = re.search(sig["pattern"], target, re.I)
            except re.error:
                continue
            if m:
                matched = True
                if len(m.groups()) >= 1 and m.group(1):
                    best_version = m.group(1)
                evidence = f"{sig.get('name') or 'html'}: {m.group(0)[:80]}"
                break
        if matched:
            existing = found.get(name)
            if existing is None:
                found[name] = {
                    "name": name,
                    "category": sigs[0].get("category", CATEGORY_DEFAULT),
                    "version": best_version,
                    "confidence": sigs[0].get("confidence", 100),
                    "evidence": evidence or name,
                }
            elif best_version and not existing.get("version"):
                existing["version"] = best_version
    return [found[k] for k in sorted(found)]
