import base64
import struct
from datetime import datetime, timedelta, timezone

from oasip.services.ctstream import _parse_leaf, matches


def _tls_encode(der: bytes) -> bytes:
    return len(der).to_bytes(3, "big") + der


def _leaf_input(der: bytes) -> str:
    ts = struct.pack(">Q", 1700000000000)
    prefix = b"\x00" + ts + struct.pack(">H", 0)
    return base64.b64encode(prefix + _tls_encode(der)).decode()


def test_parse_leaf_roundtrip():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sub.example.com")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1234)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName(
            [x509.DNSName("sub.example.com"), x509.DNSName("www.example.com")]), False)
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(Encoding.DER)
    parsed = _parse_leaf(_leaf_input(der))
    assert parsed == der
    assert matches(["sub.example.com", "www.example.com"], "example.com") == "sub.example.com"
    assert matches(["other.org"], "example.com") is None
