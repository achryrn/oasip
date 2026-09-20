from oasip.modules.correlate_module import TAKEOVER_FINGERPRINTS


def _match(service: str, body: str) -> bool:
    for svc, needles in TAKEOVER_FINGERPRINTS:
        if svc == service:
            return all(n.lower() in body.lower() for n in needles[:2])
    return False


def test_github_pages_fingerprint():
    body = "<html>There isn't a GitHub Pages site here. For root URLs (like https://example.com) you must provide</html>"
    assert _match("GitHub Pages", body)


def test_s3_fingerprint():
    body = "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"
    assert _match("AWS S3", body)


def test_no_false_positive():
    body = "<html>Welcome to example.com - a real site with content</html>"
    for svc, _ in TAKEOVER_FINGERPRINTS:
        assert not _match(svc, body), svc
