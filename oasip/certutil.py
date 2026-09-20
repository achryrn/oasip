"""Certificate parsing + identity fingerprinting shared by CT mining,
TLS capture and the fingerprint module.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding


def normalize_serial(serial) -> str:
    if serial is None:
        return ""
    if isinstance(serial, int):
        return format(serial, "x")
    return str(serial).replace(":", "").replace(" ", "").lower()


def identity_fingerprint(serial, issuer: str, not_before: str, sans: List[str]) -> str:
    """Stable cert identity across crt.sh metadata rows and live TLS capture."""
    key = "|".join([
        normalize_serial(serial),
        (issuer or "").strip().lower().replace(" ", ""),
        (not_before or "")[:19],
        "|".join(sorted(s.lower() for s in sans)),
    ])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def parse_der(der: bytes) -> Optional[Dict]:
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None
    sans: List[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = ext.get_values_for_type(x509.DNSName)
    except Exception:
        pass
    try:
        key_bits = cert.public_key().key_size
    except Exception:
        key_bits = None
    issuer = cert.issuer.rfc4514_string()
    subject = cert.subject.rfc4514_string()
    org = ""
    try:
        for attr in cert.subject:
            if attr.oid == x509.NameOID.ORGANIZATION_NAME:
                org = attr.value
                break
    except Exception:
        pass
    try:
        sig_algo = cert.signature_algorithm_oid._name
    except Exception:
        sig_algo = str(cert.signature_algorithm_oid)
    nb = cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    na = cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "sha256": hashlib.sha256(der).hexdigest(),
        "identity": identity_fingerprint(cert.serial_number, issuer, nb, sans),
        "serial": normalize_serial(cert.serial_number),
        "subject": subject,
        "issuer": issuer,
        "org": org,
        "not_before": nb,
        "not_after": na,
        "key_algo": cert.public_key().__class__.__name__,
        "key_bits": key_bits,
        "sig_algo": sig_algo,
        "sans": sans,
        "wildcard": any(s.startswith("*.") for s in sans),
        "self_signed": issuer == subject,
    }


def flags_for(cert: Dict, now: Optional[datetime] = None) -> List[str]:
    flags = []
    now = now or datetime.now(timezone.utc)
    try:
        nb = datetime.strptime(cert["not_before"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        na = datetime.strptime(cert["not_after"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        nb = na = None
    if cert.get("self_signed"):
        flags.append("self-signed")
    if cert.get("wildcard"):
        flags.append("wildcard")
    if cert.get("key_algo", "").startswith("RSA") and cert.get("key_bits") and cert["key_bits"] < 2048:
        flags.append("weak-rsa")
    if cert.get("sig_algo") and ("sha1" in cert["sig_algo"].lower() or "md5" in cert["sig_algo"].lower()):
        flags.append("weak-signature")
    if nb and na:
        if na < now:
            flags.append("expired")
        elif (na - now).days <= 30:
            flags.append("expiring")
    return flags
