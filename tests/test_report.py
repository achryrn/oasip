import json


def test_full_report_roundtrip(tmp_env):
    from oasip import repos
    from oasip.report_module import (build_report, render_html,
                                     render_markdown, render_stix)

    scan_id = repos.create_scan("example.com", "Example Corp", ["dns", "risk"])
    repos.upsert_host(scan_id, "example.com", is_root=True, ips=["93.184.216.34"],
                      dmarc_policy="none", dmarc_permissive=True,
                      spf_policy="softfail", dkim_present=False)
    repos.upsert_host(scan_id, "www.example.com", ips=["93.184.216.34"],
                      http_status=200, server_header="nginx/1.18.0")
    repos.upsert_ip(scan_id, "93.184.216.34", asn="AS15133", org_name="EdgeCast",
                    ports=[80, 443], tls_config={"versions": ["TLSv1.2"]})
    repos.upsert_technology(scan_id, "www.example.com", "Nginx", "1.18.0",
                            cvss_max=7.5, cve_ids=["CVE-2019-9511"])
    repos.upsert_breach(scan_id, "example.com", "TestBreach", pw_exposure="plaintext",
                        breach_date="2023-01-01", added_date="2023-02-01", severity="high")
    repos.add_repo_finding(scan_id, "https://github.com/example/repo", file_path=".env",
                           secret_type="AWS Access Key", tool="github-search")
    repos.upsert_takeover(scan_id, "jira.example.com", cname_target="x.netlify.app",
                          service="Netlify", status="vulnerable")
    repos.add_finding(scan_id, "breach", "high", "Domain in breach",
                      {"breach": "TestBreach"}, "", 20.0, "domain", "example.com")
    repos.finish_scan(scan_id, "done", {"hosts": 2, "ips": 1}, 42.0)

    data = build_report(scan_id)
    assert data["scope"] == "example.com"
    assert data["overall"] == 42
    assert len(data["hosts"]) == 2
    assert len(data["findings"]) == 1
    assert data["takeovers"][0]["service"] == "Netlify"

    html = render_html(data)
    assert "example.com" in html
    assert "CVE-2019-9511" in html or "Nginx" in html

    md = render_markdown(data)
    assert "## Hosts" in md

    stix = render_stix(data)
    bundle = json.dumps(stix)
    assert stix["spec_version"] == "2.1"
    assert any(o["type"] == "identity" for o in stix["objects"])
    assert any(o["type"] == "domain-name" for o in stix["objects"])
    assert any(o["type"] == "vulnerability" for o in stix["objects"])
    assert any(o["type"] == "observed-data" for o in stix["objects"])

    written = __import__("oasip.report_module", fromlist=["write_reports"]).write_reports(
        scan_id, ["html", "md", "stix"])
    for p in written:
        assert p.exists() and p.stat().st_size > 100
        if p.suffix == ".json":
            json.loads(p.read_text())
