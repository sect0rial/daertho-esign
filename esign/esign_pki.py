"""E-Sign PKI helpers: the root CA, the optional issuing CA and the document-seal certificate.

Two ways to get a seal certificate:
  * ensure_pki(data_dir) — first boot with no seal configured: a self-signed "<legal name> E-Sign Root CA" and a
    "<legal name> E-Sign Document Seal" certificate are generated into DATA_DIR/pki (directory 0700, files 0600,
    private keys encrypted with a random passphrase kept in DATA_DIR/pki/.pass). Zero-config, but the root key sits
    on the server.
  * scripts/esign_pki.py — an offline key ceremony (root -> issuing CA -> seal) for operators who want the root key
    off the server; the seal PKCS#12 then goes into ESIGN_SEAL_P12 / ESIGN_SEAL_PASS.
A certificate bought from an Adobe-trusted CA (AATL) loads the same way (ESIGN_SEAL_P12) and then shows as trusted in
Acrobat with no code change.

RSA-3072 for the seal (the widest PDF-reader support), RSA-4096 for roots. Key usage digitalSignature +
nonRepudiation (contentCommitment); EKUs documentSigning (RFC 9336) + Microsoft Document Signing + emailProtection
(Acrobat accepts the last two; validators that check documentSigning see it).
"""
from __future__ import annotations

import datetime as _dt
import os
import secrets
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from . import brand

EKU_DOC_SIGNING = ObjectIdentifier("1.3.6.1.5.5.7.3.36")
EKU_MS_DOC_SIGNING = ObjectIdentifier("1.3.6.1.4.1.311.10.3.12")


def org() -> str:
    """'<legal name> E-Sign' (not doubled when the name already ends in 'E-Sign')."""
    n = (brand.legal_name() or "").strip() or "E-Sign"
    return (n if n.lower().replace(" ", "").endswith("e-sign") else f"{n} E-Sign")[:64]


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _name(cn: str, extra: Optional[list] = None) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn[:64]),
             x509.NameAttribute(NameOID.ORGANIZATION_NAME, org())]
    return x509.Name(attrs + list(extra or []))


def new_rsa(bits: int = 3072):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _builder(subject: x509.Name, issuer: x509.Name, pub, days: int, back_minutes: int = 5):
    t = _now() - _dt.timedelta(minutes=back_minutes)
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(pub)
            .serial_number(int.from_bytes(secrets.token_bytes(16), "big") >> 1)
            .not_valid_before(t).not_valid_after(t + _dt.timedelta(days=days))
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False))


def _ca_usage():
    return x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                         crl_sign=True, encipher_only=False, decipher_only=False)


def make_root(days: int = 365 * 15, key=None, path_length: int = 1):
    key = key or new_rsa(4096)
    name = _name(f"{org()} Root CA")
    cert = (_builder(name, name, key.public_key(), days)
            .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
            .add_extension(_ca_usage(), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def _aki(issuer_cert: x509.Certificate):
    ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)


def make_issuing_ca(root_key, root_cert, days: int = 365 * 8, key=None):
    key = key or new_rsa(3072)
    cert = (_builder(_name(f"{org()} Issuing CA"), root_cert.subject, key.public_key(), days)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_ca_usage(), critical=True)
            .add_extension(_aki(root_cert), critical=False)
            .sign(root_key, hashes.SHA256()))
    return key, cert


def _end_entity(builder, issuer_cert, email_eku: bool = True):
    ekus = [EKU_DOC_SIGNING, EKU_MS_DOC_SIGNING] + ([ExtendedKeyUsageOID.EMAIL_PROTECTION] if email_eku else [])
    return (builder
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
            .add_extension(_aki(issuer_cert), critical=False))


def make_seal(ca_key, ca_cert, days: int = 365 * 3, key=None):
    key = key or new_rsa(3072)
    b = _builder(_name(f"{org()} Document Seal"), ca_cert.subject, key.public_key(), days)
    cert = _end_entity(b, ca_cert).sign(ca_key, hashes.SHA256())
    return key, cert


def to_p12(key, cert, chain: list, password: Optional[bytes], name: bytes = b"esign-seal") -> bytes:
    enc = (serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption())
    return pkcs12.serialize_key_and_certificates(name, key, cert, list(chain), enc)


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key, password: Optional[bytes]) -> bytes:
    enc = (serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption())
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)


def dev_pki(password: bytes = b"dev"):
    """A complete throwaway hierarchy (tests / local dev): returns dict with keys, certs and the seal PKCS#12."""
    rk, rc = make_root(key=new_rsa(2048))
    ck, cc = make_issuing_ca(rk, rc, key=new_rsa(2048))
    sk, sc = make_seal(ck, cc, key=new_rsa(2048))
    return {"root_key": rk, "root": rc, "ca_key": ck, "ca": cc, "seal_key": sk, "seal": sc,
            "seal_p12": to_p12(sk, sc, [cc, rc], password)}


# ------------------------------------------------------------------------------------------------ first-boot PKI
def _write(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def data_dir() -> Path:
    return Path((os.environ.get("ESIGN_DATA_DIR") or "").strip() or "./data")


def pki_paths(base: Optional[Path] = None) -> dict:
    d = Path(base or data_dir()) / "pki"
    return {"dir": d, "pass": d / ".pass", "root_key": d / "root_ca.key.pem", "root": d / "root_ca.crt",
            "seal_p12": d / "seal.p12"}


def ensure_pki(base=None, key_bits: int = 0) -> dict:
    """Make sure DATA_DIR/pki holds a root CA + document seal; generate them when missing. Returns pki_paths().
    Never overwrites an existing root. `key_bits` (tests) shrinks the keys for speed."""
    p = pki_paths(Path(base) if base else None)
    if p["seal_p12"].exists() and p["pass"].exists():
        return p
    p["dir"].mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(p["dir"], 0o700)
    except OSError:
        pass
    if p["root_key"].exists() and p["pass"].exists():     # root kept, seal lost -> re-issue the seal only
        pw = p["pass"].read_bytes().strip()
        root_key = serialization.load_pem_private_key(p["root_key"].read_bytes(), pw)
        root = x509.load_pem_x509_certificate(p["root"].read_bytes())
    else:
        pw = secrets.token_urlsafe(32).encode()
        _write(p["pass"], pw)
        root_key, root = make_root(key=new_rsa(key_bits or 4096), path_length=0)
        _write(p["root_key"], key_pem(root_key, pw))
        _write(p["root"], pem(root))
    seal_key, seal = make_seal(root_key, root, key=new_rsa(key_bits or 3072))
    _write(p["seal_p12"], to_p12(seal_key, seal, [root], pw))
    print(f"E-Sign: generated a self-signed seal certificate in {p['dir']} "
          f"(seal sha256 {seal.fingerprint(hashes.SHA256()).hex()})")
    return p
