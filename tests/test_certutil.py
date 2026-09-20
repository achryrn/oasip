from datetime import datetime, timedelta, timezone

from oasip.certutil import flags_for, identity_fingerprint


def test_identity_stable():
    a = identity_fingerprint("1A:2B", "C=US,O=Test", "2024-01-01T00:00:00", ["a.example.com", "b.example.com"])
    b = identity_fingerprint("1a2b", "C=US, O=Test", "2024-01-01T00:00:00", ["b.example.com", "a.example.com"])
    assert a == b
    c = identity_fingerprint("1A2B", "C=US,O=Other", "2024-01-01T00:00:00", ["a.example.com"])
    assert a != c


def test_flags_expired_and_weak():
    past = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cert = {"not_before": past, "not_after": past, "self_signed": True,
            "wildcard": False, "key_algo": "RSAPublicKey", "key_bits": 1024,
            "sig_algo": "sha1WithRSAEncryption"}
    flags = flags_for(cert)
    assert "expired" in flags
    assert "weak-rsa" in flags
    assert "weak-signature" in flags
    assert "self-signed" in flags


def test_flags_expiring():
    soon = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cert = {"not_before": "2024-01-01T00:00:00Z", "not_after": soon,
            "self_signed": False, "wildcard": True, "key_algo": "ECPublicKey",
            "key_bits": 256, "sig_algo": "ecdsa-with-SHA256"}
    flags = flags_for(cert)
    assert "expiring" in flags
    assert "wildcard" in flags
    assert "weak-rsa" not in flags
