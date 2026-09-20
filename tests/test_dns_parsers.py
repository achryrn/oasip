from oasip.services.resolver import parse_dmarc, parse_spf


def test_spf_parses_ranges_and_third_party():
    recs = [
        "v=spf1 ip4:203.0.113.0/24 ip6:2001:db8::/32 include:_spf.google.com include:sendgrid.net ~all",
    ]
    spf = parse_spf(recs)
    assert spf["present"] is True
    assert spf["policy"] == "softfail"
    assert "ip4:203.0.113.0/24" in spf["ip_ranges"]
    assert "_spf.google.com" in spf["third_party"]
    assert spf["permissive"] is False


def test_spf_plus_all_is_permissive():
    spf = parse_spf(["v=spf1 ip4:203.0.113.0/24 +all"])
    assert spf["policy"] == "pass"
    assert spf["permissive"] is True


def test_spf_missing():
    spf = parse_spf(["something-else-domainkey=foo"])
    assert spf["present"] is False
    assert spf["permissive"] is True


def test_dmarc_none_is_permissive():
    dmarc = parse_dmarc(["v=DMARC1; p=none; rua=mailto:dmarc@example.com"])
    assert dmarc["policy"] == "none"
    assert dmarc["permissive"] is True


def test_dmarc_reject_not_permissive():
    dmarc = parse_dmarc(["v=DMARC1; p=reject; sp=quarantine"])
    assert dmarc["policy"] == "reject"
    assert dmarc["permissive"] is False


def test_dmarc_missing():
    dmarc = parse_dmarc(["v=spf1 -all"])
    assert dmarc["policy"] == "missing"
    assert dmarc["permissive"] is True
