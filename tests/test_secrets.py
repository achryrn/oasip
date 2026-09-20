from oasip import secrets as S


def test_aws_key_detected():
    blob = "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
    found = S.classify(blob)
    assert any(f["type"] == "AWS Access Key" for f in found)
    assert any(f["severity"] == "critical" for f in found)


def test_github_token_detected():
    blob = "token = ghp_" + "A" * 36
    found = S.classify(blob)
    assert any(f["type"] == "GitHub Token" for f in found)


def test_private_key_detected():
    found = S.classify("-----BEGIN RSA PRIVATE KEY-----" + "\nMIIEowIBA")
    assert any(f["type"] == "Private Key" for f in found)


def test_conn_string_detected():
    found = S.classify("postgres://admin:hunter2@db.internal:5432/prod")
    assert any("Connection String" in f["type"] for f in found)


def test_generic_high_entropy_key():
    found = S.classify("api_key = 'x9K3mQ7vR2tY8wN5pL1zA6cB4dE0fG2h'")
    assert any(f["type"].startswith("Generic Secret") for f in found)


def test_internal_hostnames():
    out = S.extract_internal_hostnames(
        "connect to https://prod-db.internal.corp.example.com:5432 and http://jenkins.build.example.com", "example.com")
    assert "prod-db.internal.corp.example.com" in out
    assert "jenkins.build.example.com" in out


def test_conn_targets():
    targets = S.extract_conn_string_targets("mysql://u:p@db1.example.com:3306/app")
    assert "db1.example.com" in targets
