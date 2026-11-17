"""E-Sign document seal: a PAdES digital seal + RFC 3161 timestamp on every completed envelope's PDF.

What it gives: any PDF reader (Acrobat's Signatures panel, the EU DSS validator, pyHanko) can show by itself that the
completed PDF has not changed since this server sealed it, and when it was sealed (a timestamp token from an
independent time-stamping authority, not our clock). Legally this strengthens the evidence of a simple electronic
signature; it does not by itself make the signers' signatures advanced or qualified (see esign.py, "Legal posture").

Where the seal certificate comes from (esign_pki.py):
  ESIGN_SEAL_P12 / ESIGN_SEAL_PASS   a PKCS#12 with its chain (base64 text, or a path to the .p12 / base64 file) —
                                     from scripts/esign_pki.py (offline root) or bought from an Adobe-trusted CA
  otherwise                          DATA_DIR/pki, generated on first use by esign_pki.ensure_pki() (self-signed root;
                                     set ESIGN_PKI_AUTO=0 to switch that off and run unsealed)
A self-signed root is not in Adobe's trust list, so Acrobat shows the seal as intact with an unknown signer until the
reader trusts the root (downloadable from GET /v1/sign/root.crt).

Env: ESIGN_TSA_URLS (comma-separated RFC 3161 URLs, tried in order; default DigiCert, then Sectigo; "off" = no
timestamp); ESIGN_TSA_TIMEOUT (seconds per TSA, default 10); ESIGN_SEAL_FPS (fingerprints of retired seal
certificates, after a rotation); ESIGN_TRUST_PEM (extra trusted roots, e.g. a previous root). No seal -> completion
still works, unsealed, and the envelope records why. A TSA outage -> the seal is applied without a timestamp
(PAdES-B-B) and recorded as such; sealing never blocks a completion.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import io
import os
import threading
from typing import Optional

import logging

# pyHanko logs every certificate path it fails to build (e.g. a TSA chain while trying the web roots) as a warning with
# a traceback; validation outcomes are reported in our return values, so keep only its errors in the server log.
for _name in ("pyhanko", "pyhanko_certvalidator"):
    logging.getLogger(_name).setLevel(logging.ERROR)

_DEFAULT_TSA = "http://timestamp.digicert.com,http://timestamp.sectigo.com"
_lock = threading.Lock()
_cache: dict = {}

SEAL_FIELD = "DocumentSeal"
EKU_DOC_SIGNING = "1.3.6.1.5.5.7.3.36"          # id-kp-documentSigning (RFC 9336)
EKU_MS_DOC_SIGNING = "1.3.6.1.4.1.311.10.3.12"  # Microsoft Document Signing (accepted by Acrobat)


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def tsa_urls() -> list:
    raw = _env("ESIGN_TSA_URLS") or _DEFAULT_TSA
    if raw.lower() in ("off", "none", "0"):
        return []
    return [u.strip() for u in raw.split(",") if u.strip()]


def tsa_host(url: Optional[str]) -> Optional[str]:
    """A TSA URL as it may be shown or stored: the host only (a paid TSA URL can carry credentials or a key)."""
    if not url:
        return None
    from urllib.parse import urlsplit
    try:
        return urlsplit(url).hostname or "time-stamping service"
    except Exception:
        return "time-stamping service"


def _p12_bytes(raw: str) -> bytes:
    """ESIGN_SEAL_P12 as given: base64 text, or a path to a .p12 file (binary or base64 inside)."""
    if len(raw) < 1024 and os.path.isfile(raw):
        data = open(raw, "rb").read()
        try:
            return base64.b64decode(data, validate=False) if data[:1] != b"0" else data
        except Exception:
            return data
    return base64.b64decode(raw)


def _load_p12_data(data: bytes, pw: Optional[bytes], label: str):
    """(pyHanko SimpleSigner, [asn1crypto certs: leaf..root], cryptography key) from PKCS#12 bytes. Cached on the
    content, so a rotated key is picked up without a restart."""
    key = (label, hashlib.sha256(data).hexdigest(), pw)
    with _lock:
        hit = _cache.get(key)
        if hit is not None:
            return hit
        from cryptography.hazmat.primitives.serialization import pkcs12
        from asn1crypto import keys as a_keys, x509 as a_x509
        from pyhanko.sign import signers
        from pyhanko_certvalidator.registry import SimpleCertificateStore
        from cryptography.hazmat.primitives import serialization as ser
        k, cert, extra = pkcs12.load_key_and_certificates(data, pw or None)
        if k is None or cert is None:
            raise ValueError(f"{label}: no key/certificate in the PKCS#12")
        leaf = a_x509.Certificate.load(cert.public_bytes(ser.Encoding.DER))
        chain = [a_x509.Certificate.load(c.public_bytes(ser.Encoding.DER)) for c in (extra or [])]
        sk = a_keys.PrivateKeyInfo.load(k.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8,
                                                        ser.NoEncryption()))
        signer = signers.SimpleSigner(signing_cert=leaf, signing_key=sk,
                                      cert_registry=SimpleCertificateStore.from_certs(chain))
        out = (signer, [leaf] + _order_chain(leaf, chain), k)
        if len(_cache) > 8:
            _cache.clear()
        _cache[key] = out
        return out


def _order_chain(leaf, chain: list) -> list:
    """The issuers of `leaf` in order up to the root (whatever of them the PKCS#12 carries)."""
    by_subject = {c.subject.dump(): c for c in chain}
    out, cur, seen = [], leaf, set()
    while cur.issuer.dump() in by_subject and cur.issuer.dump() != cur.subject.dump():
        nxt = by_subject[cur.issuer.dump()]
        if id(nxt) in seen:
            break
        seen.add(id(nxt))
        out.append(nxt)
        cur = nxt
    return out


def seal_identity():
    """The seal signer: ESIGN_SEAL_P12 if set, else the auto-generated DATA_DIR/pki seal (created on first use unless
    ESIGN_PKI_AUTO=0), else None."""
    raw = _env("ESIGN_SEAL_P12")
    if raw:
        return _load_p12_data(_p12_bytes(raw), _env("ESIGN_SEAL_PASS").encode() or None, "ESIGN_SEAL_P12")
    from . import esign_pki as PKI
    p = PKI.pki_paths()
    if not (p["seal_p12"].exists() and p["pass"].exists()):
        if _env("ESIGN_PKI_AUTO") == "0":
            return None
        with _gen_lock:
            p = PKI.ensure_pki()
    return _load_p12_data(p["seal_p12"].read_bytes(), p["pass"].read_bytes().strip(), str(p["seal_p12"]))


_gen_lock = threading.Lock()


def _fp(cert) -> str:
    return hashlib.sha256(cert.dump()).hexdigest()


def cert_summary(cert) -> dict:
    return {"subject": cert.subject.human_friendly, "issuer": cert.issuer.human_friendly,
            "serial": format(cert.serial_number, "x"), "sha256": _fp(cert),
            "not_after": cert["tbs_certificate"]["validity"]["not_after"].native.isoformat()}


def root_cert():
    """The top of the configured seal chain (the E-Sign Root CA), or None."""
    ident = seal_identity()
    return ident[1][-1] if ident else None


def root_pem() -> Optional[bytes]:
    c = root_cert()
    if c is None:
        return None
    b64 = base64.encodebytes(c.dump()).decode().replace("\n", "")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n").encode()


def _not_after(cert) -> _dt.datetime:
    return cert["tbs_certificate"]["validity"]["not_after"].native


def seal_fingerprints() -> set:
    """SHA-256 fingerprints of the certificates that ARE this server's seal: the configured seal certificate plus
    any retired ones listed in ESIGN_SEAL_FPS (comma-separated, after a rotation). Pinned so that no other
    certificate under the same root can pass for the seal."""
    fps = {x.strip().lower() for x in _env("ESIGN_SEAL_FPS").split(",") if x.strip()}
    try:
        ident = seal_identity()
        if ident:
            fps.add(_fp(ident[1][0]))
    except Exception:
        pass
    return fps


def status() -> dict:
    """What a completion will do: for the certificate page and the owner UI."""
    try:
        ident = seal_identity()
    except Exception as e:                       # a broken key must never break completion
        return {"configured": False, "error": f"seal certificate could not be loaded: {type(e).__name__}"}
    if not ident:
        return {"configured": False}
    leaf = ident[1][0]
    days_left = (_not_after(leaf) - _dt.datetime.now(_dt.timezone.utc)).days
    if days_left < 0:
        return {"configured": False, "error": "the seal certificate has expired", "cert": cert_summary(leaf)}
    return {"configured": True, "cert": cert_summary(leaf), "root": cert_summary(ident[1][-1]),
            "tsa": [tsa_host(u) for u in tsa_urls()], "expires_in_days": days_left,
            "expiring_soon": days_left < 60}


# ------------------------------------------------------------------------------------------------ sealing
def _sign(pdf: bytes, signer, field: str, reason: str, location: Optional[str], timestamper, name: Optional[str]):
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers, fields
    w = IncrementalPdfFileWriter(io.BytesIO(pdf), strict=False)
    meta = signers.PdfSignatureMetadata(field_name=field, md_algorithm="sha256", reason=reason, location=location,
                                        name=name, subfilter=fields.SigSeedSubFilter.PADES,
                                        use_pades_lta=False)
    out = signers.sign_pdf(w, meta, signer=signer, timestamper=timestamper, existing_fields_only=False)
    return out.getvalue()


def seal_pdf(pdf: bytes, reason: Optional[str] = None,
             location: Optional[str] = None) -> tuple:
    """(bytes, info). Seals `pdf` with the configured document-seal certificate as an incremental PAdES signature,
    timestamped by the first TSA that answers. Never raises: on any failure the input comes back unchanged and
    `info` says why, so a completion is never blocked by the seal."""
    from . import brand
    reason = reason or f"Sealed by {brand.name()}: the envelope is complete"
    t0 = _dt.datetime.now(_dt.timezone.utc)
    try:
        ident = seal_identity()
    except Exception as e:
        return pdf, {"sealed": False, "reason": f"seal certificate could not be loaded ({type(e).__name__})"}
    if not ident:
        return pdf, {"sealed": False, "reason": "no seal certificate configured"}
    signer, chain, _ = ident
    if _not_after(chain[0]) <= t0:
        return pdf, {"sealed": False, "reason": "the seal certificate has expired"}
    from pyhanko.sign import timestamps
    timeout = float(_env("ESIGN_TSA_TIMEOUT") or 10)
    errors = []
    for url in tsa_urls():
        try:
            out = _sign(pdf, signer, SEAL_FIELD, reason, location,
                        timestamps.HTTPTimeStamper(url, timeout=timeout), brand.name())
            return out, {"sealed": True, "level": "PAdES-B-T", "tsa": tsa_host(url), "cert": cert_summary(chain[0]),
                         "sealed_at": t0.isoformat(), "sha256": hashlib.sha256(out).hexdigest()}
        except Exception as e:                   # TSA down / slow / bad response: try the next, then seal untimed
            errors.append(f"{tsa_host(url)}: {type(e).__name__}")
    try:
        out = _sign(pdf, signer, SEAL_FIELD, reason, location, None, brand.name())
        return out, {"sealed": True, "level": "PAdES-B-B", "tsa": None, "tsa_errors": errors,
                     "cert": cert_summary(chain[0]), "sealed_at": t0.isoformat(),
                     "sha256": hashlib.sha256(out).hexdigest()}
    except Exception as e:
        return pdf, {"sealed": False, "reason": f"sealing failed ({type(e).__name__}: {str(e)[:160]})",
                     "tsa_errors": errors}


# ------------------------------------------------------------------------------------------------ validation
def _trust_roots() -> list:
    roots = []
    c = root_cert()
    if c is not None:
        roots.append(c)
    extra = _env("ESIGN_TRUST_PEM")         # e.g. a previous root after a rotation
    if extra:
        from asn1crypto import pem, x509 as a_x509
        for _t, _h, der in pem.unarmor(extra.encode(), multiple=True):
            roots.append(a_x509.Certificate.load(der))
    return roots


def _public_roots() -> list:
    """Web PKI roots (certifi) — used only to check the TSA's own certificate chain."""
    try:
        import certifi
        from asn1crypto import pem, x509 as a_x509
        with open(certifi.where(), "rb") as f:
            return [a_x509.Certificate.load(der) for _t, _h, der in pem.unarmor(f.read(), multiple=True)]
    except Exception:
        return []


def validate(pdf: bytes) -> dict:
    """Every digital signature in `pdf`, checked: intact (bytes unchanged since signing), signer chain against the
    configured roots, whether the file was modified after it (and how), and the timestamp. When an intact, trusted RFC 3161
    timestamp is present, the signer's certificate is judged at the timestamp's time (so a seal made while its
    certificate was valid stays valid after the certificate expires). Never raises."""
    try:
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign.validation import validate_pdf_signature
        from pyhanko_certvalidator import ValidationContext
        r = PdfFileReader(io.BytesIO(pdf), strict=False)
        sigs = list(r.embedded_signatures)
    except Exception as e:
        return {"ok": False, "signatures": [], "error": f"not a readable PDF ({type(e).__name__})"}
    roots = _trust_roots()
    ts_roots = _public_roots()
    out = []
    for s in sigs:
        item = {"field": s.field_name}
        try:
            def run(moment=None):
                vc = ValidationContext(trust_roots=roots, allow_fetching=False, revocation_mode="soft-fail",
                                       moment=moment)
                tvc = ValidationContext(trust_roots=ts_roots, allow_fetching=False, revocation_mode="soft-fail")
                return validate_pdf_signature(s, signer_validation_context=vc, ts_validation_context=tvc)
            st = run()
            tsv = st.timestamp_validity
            at_ts = False
            if not st.trusted and tsv is not None and tsv.intact and tsv.valid and tsv.trusted and tsv.timestamp:
                st2 = run(tsv.timestamp)                # e.g. the seal certificate expired after sealing
                if st2.trusted:
                    st, at_ts = st2, True
            cert = st.signing_cert
            item.update({
                "intact": bool(st.intact), "valid": bool(st.valid), "trusted": bool(st.trusted),
                "trusted_at_timestamp": at_ts,
                "signer": cert.subject.human_friendly if cert is not None else None,
                "signer_sha256": _fp(cert) if cert is not None else None,
                "coverage": getattr(st.coverage, "name", str(st.coverage)),
                "modification_level": getattr(st.modification_level, "name", str(st.modification_level)),
                "docmdp_ok": getattr(st, "docmdp_ok", None),
                "signed_at": st.signer_reported_dt.isoformat() if st.signer_reported_dt else None,
            })
            tsv = st.timestamp_validity
            if tsv is not None:
                item["timestamp"] = {"at": tsv.timestamp.isoformat() if tsv.timestamp else None,
                                     "intact": bool(tsv.intact), "valid": bool(tsv.valid),
                                     "trusted": bool(tsv.trusted)}
        except Exception as e:
            item.update({"intact": False, "valid": False, "error": f"{type(e).__name__}: {str(e)[:160]}"})
        out.append(item)
    return {"ok": True, "signatures": out}


def summarize(v: dict) -> dict:
    """The verdict a person needs from validate(): sealed by this server? unchanged since? when? A seal counts as
    ours only if its certificate chains to our root AND is one of the pinned seal certificates (seal_fingerprints);
    anything else in the seal field is reported as a seal we can't confirm, whatever its coverage."""
    from . import brand
    b = brand.name()
    seals = [s for s in v.get("signatures") or [] if s.get("field") == SEAL_FIELD]
    if not seals:
        return {"sealed": False, "verdict": f"no {b} seal in this file"}
    s = seals[-1]
    pinned = (s.get("signer_sha256") or "") in seal_fingerprints()      # carries our seal certificate
    ours = pinned and bool(s.get("trusted"))
    unchanged = bool(s.get("intact")) and s.get("coverage") == "ENTIRE_FILE"
    if pinned and s.get("valid") and not s.get("intact"):   # a genuine seal whose content changed (a forged CMS
        # carrying the public seal certificate but not signed by its key is "can't confirm", below)
        verdict = "seal broken: the sealed content was altered"           # (pyHanko then also reports untrusted)
    elif not ours:
        verdict = f"a seal {b} can't confirm: it was not made with the {b} seal certificate"
    elif unchanged:
        verdict = f"sealed by {b} and unchanged since"
    else:
        verdict = f"sealed by {b}, but the file was changed after sealing"
    return {"sealed": True, "unchanged": bool(unchanged and ours), "trusted": ours, "verdict": verdict,
            "claimed_signer": s.get("signer"), "signer": s.get("signer") if ours else None,
            "timestamp": s.get("timestamp"), "signed_at": s.get("signed_at") if ours else None,
            "trusted_at_timestamp": bool(s.get("trusted_at_timestamp")) and ours}
