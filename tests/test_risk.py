from oasip.modules.risk_module import score_host, score_ip


def test_host_dmarc_permissive():
    h = __import__("types").SimpleNamespace(
        dmarc_permissive=True, spf_permissive=False, cert_expiry=None, dns_records={})
    assert score_host(h) >= 8


def test_host_expired_cert():
    h = __import__("types").SimpleNamespace(
        dmarc_permissive=False, spf_permissive=False, cert_expiry="2020-01-01", dns_records={})
    assert score_host(h) == 10


def test_ip_tls10():
    i = __import__("types").SimpleNamespace(
        tls_config={"versions": ["TLSv1.0", "TLSv1.2"]}, banners=[], ssh_keys=[])
    assert score_ip(i) >= 7


def test_ip_clean():
    i = __import__("types").SimpleNamespace(
        tls_config={"versions": ["TLSv1.2", "TLSv1.3"]}, banners=[], ssh_keys=[])
    assert score_ip(i) == 0
