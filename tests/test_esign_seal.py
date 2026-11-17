"""E-Sign document seal: every completed PDF is sealed (PAdES + RFC 3161 timestamp), Verify checks the seal,
the root certificate is public, and a recipient can be required to enter a one-time code emailed to them.

The TSA is a local dummy (pyHanko's DummyTimeStamper with a throwaway TSA certificate), so no network is needed.
Run: .venv/bin/pytest -q tests/test_esign_seal.py
"""
import base64
import datetime as dt
import io
import json
import re

import pytest

pytest.importorskip("pyhanko")
pytest.importorskip("reportlab")
pytest.importorskip("pypdfium2")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

from esign import esign, esign_pki as K, esign_seal as SEAL  # noqa: E402
from test_esign import A, _links, _new_env, _pdf, _sent_single, _sign_fields, _tok, _upload, ctx  # noqa: E402,F401


# ------------------------------------------------------------------------------------------------- fixtures
@pytest.fixture(scope="module")
def pki():
    return K.dev_pki(password=b"pw")


@pytest.fixture(scope="module")
def tsa():
    """A throwaway TSA certificate + key (EKU timeStamping, critical) for pyHanko's DummyTimeStamper."""
    key = K.new_rsa(2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA")])
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(7).not_valid_before(now).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
            .sign(key, hashes.SHA256()))
    from asn1crypto import keys as a_keys, x509 as a_x509
    return (a_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER)),
            a_keys.PrivateKeyInfo.load(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption())))


@pytest.fixture
def sealed_env(monkeypatch, pki, tsa):
    """Seal configured; the 'TSA' answers locally."""
    from pyhanko.sign import timestamps
    from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper
    monkeypatch.setenv("ESIGN_SEAL_P12", base64.b64encode(pki["seal_p12"]).decode())
    monkeypatch.setenv("ESIGN_SEAL_PASS", "pw")
    monkeypatch.setenv("ESIGN_TSA_URLS", "http://tsa.invalid/1,http://tsa.invalid/2")
    calls = []

    def fake(url, timeout=None, **kw):
        calls.append(url)
        return DummyTimeStamper(tsa_cert=tsa[0], tsa_key=tsa[1])
    monkeypatch.setattr(timestamps, "HTTPTimeStamper", fake)
    return calls


def _sign(c, tok):
    c.post(f"/v1/sign/{tok}/consent")
    return _sign_fields(c, tok)


def _complete_one(c, **kw):
    eid, doc, s, tok = _sent_single(c, **kw)
    r = _sign(c, tok)
    assert r.status_code == 200, r.text
    env = c.get(f"/v1/esign/envelopes/{eid}", headers=A).json()
    assert env["status"] == "completed"
    return eid, env, tok


def _download(c, eid, kind="combined"):
    r = c.get(f"/v1/esign/envelopes/{eid}/download?kind={kind}", headers=A)
    assert r.status_code == 200
    return r.content


# ------------------------------------------------------------------------------------------------- the seal
def test_completed_pdf_is_sealed_and_timestamped(ctx, sealed_env, pki):
    c, repo = ctx
    eid, env, _ = _complete_one(c)
    seal = env["final"]["seal"]
    assert seal["sealed"] and seal["level"] == "PAdES-B-T" and seal["tsa"] == "tsa.invalid"
    assert seal["cert_subject"].endswith("Daertho E-Sign Document Seal")
    final = _download(c, eid)
    assert SEAL.validate(final)["signatures"][0]["timestamp"]["intact"] is True
    s = SEAL.summarize(SEAL.validate(final))
    assert s == {**s, "sealed": True, "unchanged": True, "trusted": True,
                 "verdict": "sealed by Daertho E-Sign and unchanged since"}
    assert env["final"]["sha256"] == __import__("hashlib").sha256(final).hexdigest()   # the hash is of the sealed file
    ev = [e for e in repo._docs[eid]["parsed"]["events"] if e["event"] == "sealed"][-1]
    assert ev["detail"]["seal_cert_sha256"] == seal["cert_sha256"] and "sealed (PAdES-B-T)" in ev["detail"]["note"]
    raw = str(repo._docs[eid]["parsed"])
    assert "PRIVATE" not in raw and "seal_p12" not in raw


def test_certificate_page_states_the_seal_and_the_excerpt_is_sealed_too(ctx, sealed_env):
    from pypdf import PdfReader
    c, _ = ctx
    eid, env, _ = _complete_one(c)
    final = _download(c, eid)
    rd = PdfReader(io.BytesIO(final))
    cert_text = " ".join(" ".join(p.extract_text() for p in rd.pages[-env["final"]["cert_pages"]:]).split())
    assert "Digital seal" in cert_text and "Daertho E-Sign Document Seal" in cert_text
    assert "not sealed with a digital certificate" not in cert_text
    excerpt = _download(c, eid, "certificate")
    assert SEAL.summarize(SEAL.validate(excerpt))["unchanged"] is True


def test_a_tsa_outage_seals_without_a_timestamp(ctx, sealed_env, monkeypatch):
    from pyhanko.sign import timestamps

    def down(url, timeout=None, **kw):
        raise ConnectionError("TSA unreachable")
    monkeypatch.setattr(timestamps, "HTTPTimeStamper", down)
    c, _ = ctx
    eid, env, _ = _complete_one(c)
    seal = env["final"]["seal"]
    assert seal["sealed"] and seal["level"] == "PAdES-B-B" and seal["tsa"] is None and len(seal["tsa_errors"]) == 2
    assert SEAL.summarize(SEAL.validate(_download(c, eid)))["unchanged"] is True


def test_the_second_tsa_is_used_when_the_first_fails(ctx, sealed_env, monkeypatch, tsa):
    from pyhanko.sign import timestamps
    from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper

    def flaky(url, timeout=None, **kw):
        if url.endswith("/1"):
            raise TimeoutError("slow")
        return DummyTimeStamper(tsa_cert=tsa[0], tsa_key=tsa[1])
    monkeypatch.setattr(timestamps, "HTTPTimeStamper", flaky)
    c, _ = ctx
    _, env, _ = _complete_one(c)
    assert env["final"]["seal"]["tsa"] == "tsa.invalid" and env["final"]["seal"]["level"] == "PAdES-B-T"


def test_without_a_seal_certificate_completion_still_works(ctx, monkeypatch):
    monkeypatch.delenv("ESIGN_SEAL_P12", raising=False)
    c, repo = ctx
    eid, env, _ = _complete_one(c)
    assert env["final"]["seal"] == {"sealed": False, "reason": "no seal certificate configured"}
    assert SEAL.summarize(SEAL.validate(_download(c, eid)))["sealed"] is False
    ev = [e for e in repo._docs[eid]["parsed"]["events"] if e["event"] == "sealed"][-1]
    assert ev["detail"]["seal"] == "not sealed: no seal certificate configured"


def test_a_broken_seal_key_never_blocks_completion(ctx, monkeypatch):
    monkeypatch.setenv("ESIGN_SEAL_P12", base64.b64encode(b"not a pkcs12").decode())
    c, _ = ctx
    _, env, _ = _complete_one(c)
    assert env["final"]["seal"]["sealed"] is False and "could not be loaded" in env["final"]["seal"]["reason"]


def test_verify_checks_the_seal_and_catches_tampering(ctx, sealed_env):
    c, _ = ctx
    eid, env, _ = _complete_one(c)
    final = _download(c, eid)
    ok = c.post("/v1/esign/verify", headers=A, files={"file": ("x.pdf", final, "application/pdf")}).json()
    assert ok["match"] and ok["kind"] == "final" and ok["seal"]["verdict"] == "sealed by Daertho E-Sign and unchanged since"
    edited = final + b"\n%% appended after sealing\n"
    bad = c.post("/v1/esign/verify", headers=A, files={"file": ("x.pdf", edited, "application/pdf")}).json()
    assert bad["match"] is False and bad["seal"]["unchanged"] is False
    assert bad["seal"]["verdict"] == "sealed by Daertho E-Sign, but the file was changed after sealing"


def test_root_certificate_is_public_and_matches_the_chain(ctx, sealed_env, pki, monkeypatch):
    c, _ = ctx
    r = c.get("/v1/sign/root.crt")
    assert r.status_code == 200 and r.content.startswith(b"-----BEGIN CERTIFICATE-----")
    got = x509.load_pem_x509_certificate(r.content)
    assert got.fingerprint(hashes.SHA256()) == pki["root"].fingerprint(hashes.SHA256())
    monkeypatch.delenv("ESIGN_SEAL_P12")
    assert c.get("/v1/sign/root.crt").status_code == 404


def test_config_reports_seal_and_email_capability(ctx, sealed_env, monkeypatch):
    c, _ = ctx
    monkeypatch.delenv("ESIGN_SMTP_HOST", raising=False)
    cfg = c.get("/v1/esign/config", headers=A).json()
    assert cfg["seal"]["configured"] and cfg["seal"]["level"] == "PAdES-B-T" and cfg["email_codes"] is False
    assert c.get("/v1/esign/config").status_code == 401


# ------------------------------------------------------------------------------------------------- email codes
@pytest.fixture
def mail(monkeypatch):
    monkeypatch.setenv("ESIGN_SMTP_HOST", "smtp.invalid")
    monkeypatch.setenv("ESIGN_MAIL", "0")          # these tests are about email codes: links aren't emailed
    sent = []
    monkeypatch.setattr(esign, "_send_mail", lambda to, subject, body: sent.append((to, subject, body)))
    return sent


def _code(sent):
    return re.search(r"\b(\d{6})\b", sent[-1][1]).group(1)


def _sent_email_code(c, access_code=None):
    eid = _new_env(c)
    doc = _upload(c, eid).json()
    rec = {"name": "Sam Signer", "email": "sam.signer@example.com", "role": "signer", "email_code": True}
    if access_code:
        rec["access_code"] = access_code
    r = c.put(f"/v1/esign/envelopes/{eid}/recipients", headers=A, json={"recipients": [rec]})
    assert r.status_code == 200, r.text
    s = r.json()["recipients"][0]
    c.put(f"/v1/esign/envelopes/{eid}/fields", headers=A, json={"fields": [dict(
        recipient_id=s["id"], document_id=doc["id"], page=1, type="signature", x=.5, y=.8, w=.25, h=.05)]})
    assert c.post(f"/v1/esign/envelopes/{eid}/send", headers=A).status_code == 200
    return eid, doc, s, _tok(_links(c, eid)[1]["Sam Signer"]["link"])


def test_email_codes_need_smtp(ctx, monkeypatch):
    monkeypatch.delenv("ESIGN_SMTP_HOST", raising=False)
    c, _ = ctx
    eid = _new_env(c)
    r = c.put(f"/v1/esign/envelopes/{eid}/recipients", headers=A, json={"recipients": [
        {"name": "Sam", "email": "sam@example.com", "role": "signer", "email_code": True}]})
    assert r.status_code == 422 and "outgoing mail server" in r.json()["detail"]


def test_access_code_then_email_code_then_documents(ctx, mail):
    c, repo = ctx
    eid, doc, s, tok = _sent_email_code(c, access_code="4321")
    assert s["email_code"] is True and not any(k.startswith("ec_") for k in s)
    assert c.get(f"/v1/sign/{tok}/session").json()["state"] == "access_code"
    assert c.post(f"/v1/sign/{tok}/email-code").status_code == 409            # the access code comes first
    assert c.post(f"/v1/sign/{tok}/access", json={"code": "4321"}).status_code == 200
    g = c.get(f"/v1/sign/{tok}/session").json()
    assert g["state"] == "email_code" and g["documents"] == [] and g["recipient"]["email"] is None
    assert g["email_masked"].startswith("s") and g["email_masked"].endswith("@example.com") and g["code_sent"] is False
    assert c.get(f"/v1/sign/{tok}/pages/{doc['id']}/1.png").status_code == 403
    assert _sign(c, tok).status_code == 401
    sent = c.post(f"/v1/sign/{tok}/email-code")
    assert sent.status_code == 200 and sent.json()["code_sent"] is True and mail[-1][0] == "sam.signer@example.com"
    code = _code(mail)
    assert code not in str(repo._docs[eid]["parsed"])                          # only a salted hash is stored
    bad = c.post(f"/v1/sign/{tok}/email-code/verify", json={"code": "000000" if code != "000000" else "111111"})
    assert bad.status_code == 401 and bad.json()["attempts_left"] == 4
    ok = c.post(f"/v1/sign/{tok}/email-code/verify", json={"code": code[:3] + " " + code[3:]})
    assert ok.status_code == 200 and any(k.startswith("esign_ec_") for k in ok.cookies.keys())
    assert c.get(f"/v1/sign/{tok}/session").json()["state"] == "active"
    assert c.post(f"/v1/sign/{tok}/email-code/verify", json={"code": code}).status_code == 409   # single use
    assert _sign(c, tok).status_code == 200
    env = c.get(f"/v1/esign/envelopes/{eid}", headers=A).json()
    assert env["status"] == "completed" and env["recipients"][0]["email_verified_at"]
    evs = [e["event"] for e in repo._docs[eid]["parsed"]["events"]]
    assert {"email_code_sent", "email_code_failed", "email_code_ok"} <= set(evs)


def test_email_code_resend_gap_hourly_cap_expiry_and_lock(ctx, mail):
    c, repo = ctx
    eid, doc, s, tok = _sent_email_code(c)
    rec = lambda: repo._docs[eid]["parsed"]["recipients"][0]                    # noqa: E731
    assert c.post(f"/v1/sign/{tok}/email-code").status_code == 200
    again = c.post(f"/v1/sign/{tok}/email-code")
    assert again.status_code == 429 and again.json()["resend_in"] > 0
    rec()["ec_expires"] = "2000-01-01T00:00:00Z"                                # time passes: the code expires
    assert c.post(f"/v1/sign/{tok}/email-code/verify", json={"code": _code(mail)}).status_code == 410
    esign._RL.clear()
    for _ in range(4):                                                           # hourly cap: 5 sends
        rec()["ec_last_sent"] = "2000-01-01T00:00:00Z"
        assert c.post(f"/v1/sign/{tok}/email-code").status_code == 200
        esign._RL.clear()
    rec()["ec_last_sent"] = "2000-01-01T00:00:00Z"
    capped = c.post(f"/v1/sign/{tok}/email-code")
    assert capped.status_code == 429 and "hour" in capped.json()["detail"]
    for i in range(4):
        assert c.post(f"/v1/sign/{tok}/email-code/verify", json={"code": "999999x"}).status_code == 401
    locked = c.post(f"/v1/sign/{tok}/email-code/verify", json={"code": "999999x"})
    assert locked.status_code == 429 and locked.json()["locked_until"]
    assert c.post(f"/v1/sign/{tok}/email-code/verify", json={"code": _code(mail)}).status_code == 429


def test_smtp_failure_is_reported_and_logged(ctx, mail, monkeypatch):
    c, repo = ctx
    eid, doc, s, tok = _sent_email_code(c)

    def boom(*a):
        raise OSError("smtp down")
    monkeypatch.setattr(esign, "_send_mail", boom)
    r = c.post(f"/v1/sign/{tok}/email-code")
    assert r.status_code == 502
    ev = repo._docs[eid]["parsed"]["events"][-1]
    assert ev["event"] == "email_code_failed" and "not sent" in ev["detail"]["note"]


def test_correcting_the_email_needs_a_fresh_code(ctx, mail):
    c, _ = ctx
    eid, doc, s, tok = _sent_email_code(c)
    c.post(f"/v1/sign/{tok}/email-code")
    assert c.post(f"/v1/sign/{tok}/email-code/verify", json={"code": _code(mail)}).status_code == 200
    r = c.patch(f"/v1/esign/envelopes/{eid}/recipients/{s['id']}", headers=A, json={"email": "new@example.com"})
    assert r.status_code == 200 and r.json()["email_code"] is True
    tok2 = _tok(_links(c, eid)[1]["Sam Signer"]["link"])
    assert c.get(f"/v1/sign/{tok2}/session").json()["state"] == "email_code"
    c.post(f"/v1/sign/{tok2}/email-code")
    assert mail[-1][0] == "new@example.com"


def test_owner_can_switch_the_email_code_on_an_in_progress_recipient(ctx, mail):
    c, _ = ctx
    eid, doc, s, tok = _sent_single(c)
    assert c.get(f"/v1/sign/{tok}/session").json()["state"] == "active"
    r = c.patch(f"/v1/esign/envelopes/{eid}/recipients/{s['id']}", headers=A, json={"email_code": True})
    assert r.status_code == 200 and r.json()["email_code"] is True
    assert c.get(f"/v1/sign/{tok}/session").json()["state"] == "email_code"


# ------------------------------------------------------------------------------------------------- review fixes
def test_only_the_pinned_seal_certificate_counts_as_our_seal(ctx, sealed_env, pki):
    """Another certificate from the same issuing CA must not pass for the configured seal (it is pinned)."""
    import io as _io
    from pyhanko.sign import signers
    from asn1crypto import keys as a_keys, x509 as a_x509
    from pyhanko_certvalidator.registry import SimpleCertificateStore
    from reportlab.pdfgen import canvas
    k, cert = K.make_seal(pki["ca_key"], pki["ca"], key=K.new_rsa(2048))
    cert = cert  # a second, unpinned end-entity certificate under the same CA
    der = lambda c: a_x509.Certificate.load(c.public_bytes(serialization.Encoding.DER))       # noqa: E731
    signer = signers.SimpleSigner(
        signing_cert=der(cert), signing_key=a_keys.PrivateKeyInfo.load(k.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
        cert_registry=SimpleCertificateStore.from_certs([der(pki["ca"]), der(pki["root"])]))
    b = _io.BytesIO(); cv = canvas.Canvas(b); cv.drawString(72, 750, "Pay 1,000,000"); cv.showPage(); cv.save()
    forged = SEAL._sign(b.getvalue(), signer, SEAL.SEAL_FIELD, "forged", None, None, "Mallory")
    v = SEAL.validate(forged)
    assert v["signatures"][0]["trusted"] is True                  # it does chain to our root...
    s = SEAL.summarize(v)
    assert s["trusted"] is False and s["unchanged"] is False      # ...but it is not our seal
    assert s["verdict"].startswith("a seal Daertho E-Sign can't confirm") and s["signer"] is None
    assert s["claimed_signer"]


def test_a_failed_seal_never_leaves_a_seal_claim_in_the_pdf(ctx, sealed_env, monkeypatch):
    from pypdf import PdfReader
    def boom(*a, **k):
        raise RuntimeError("signing backend down")
    monkeypatch.setattr(SEAL, "_sign", boom)
    c, _ = ctx
    eid, env, tok = _complete_one(c)
    assert env["final"]["seal"]["sealed"] is False
    final = _download(c, eid)
    text = " ".join(" ".join(p.extract_text() for p in PdfReader(io.BytesIO(final)).pages).split())
    assert "Digital seal" not in text and "not sealed with a digital certificate" in text
    s = c.get(f"/v1/sign/{tok}/session").json()
    assert s["can_download"] is True and s["sealed"] is False   # the signer page won't claim a seal either


def test_signer_session_reports_the_seal(ctx, sealed_env):
    c, _ = ctx
    _, env, tok = _complete_one(c)
    assert c.get(f"/v1/sign/{tok}/session").json()["sealed"] is True


def test_certificate_is_sealed_once_and_verifies_as_the_certificate(ctx, sealed_env, monkeypatch):
    c, _ = ctx
    eid, env, _ = _complete_one(c)
    assert env["final"]["certificate_sha256"]
    from pyhanko.sign import timestamps
    def no_tsa(*a, **k):
        raise AssertionError("no time-stamping round trip on download")
    monkeypatch.setattr(timestamps, "HTTPTimeStamper", no_tsa)
    cert = _download(c, eid, "certificate")
    assert __import__("hashlib").sha256(cert).hexdigest() == env["final"]["certificate_sha256"]
    r = c.post("/v1/esign/verify", headers=A, files={"file": ("c.pdf", cert, "application/pdf")}).json()
    assert r["match"] and r["kind"] == "certificate" and r["seal"]["unchanged"]


def test_seal_stays_valid_after_its_certificate_expires(ctx, sealed_env, monkeypatch):
    """Judged at the (trusted) timestamp's time, not today's."""
    import datetime as _d
    from pyhanko_certvalidator import ValidationContext
    c, _ = ctx
    eid, env, _ = _complete_one(c)
    final = _download(c, eid)
    real_init = ValidationContext.__init__
    later = _d.datetime.now(_d.timezone.utc) + _d.timedelta(days=365 * 5)

    def init(self, *a, moment=None, **k):
        return real_init(self, *a, moment=moment or later, **k)
    monkeypatch.setattr(ValidationContext, "__init__", init)
    monkeypatch.setattr(SEAL, "_public_roots", lambda: [])
    v = SEAL.validate(final)
    # the dummy TSA isn't a web root, so its timestamp isn't trusted here: then the seal is judged today and fails
    assert v["signatures"][0]["trusted"] is False
    monkeypatch.setattr(SEAL, "_public_roots", lambda: [_tsa_root()])
    v2 = SEAL.validate(final)
    assert v2["signatures"][0]["trusted"] is True and v2["signatures"][0]["trusted_at_timestamp"] is True
    assert SEAL.summarize(v2)["verdict"] == "sealed by Daertho E-Sign and unchanged since"


_TSA_HOLDER = {}


def _tsa_root():
    return _TSA_HOLDER["cert"]


@pytest.fixture(autouse=True)
def _remember_tsa(tsa):
    _TSA_HOLDER["cert"] = tsa[0]


def test_an_expired_seal_certificate_is_not_used(monkeypatch):
    import datetime as _d
    old = K.dev_pki(password=b"pw")
    ck, cc = old["ca_key"], old["ca"]
    sk, sc = K.make_seal(ck, cc, days=0)                      # expires immediately
    monkeypatch.setenv("ESIGN_SEAL_P12", base64.b64encode(K.to_p12(sk, sc, [cc, old["root"]], b"pw")).decode())
    monkeypatch.setenv("ESIGN_SEAL_PASS", "pw")
    st = SEAL.status()
    assert st["configured"] is False and "expired" in st["error"]
    out, info = SEAL.seal_pdf(_pdf())
    assert info == {"sealed": False, "reason": "the seal certificate has expired"}


def test_email_code_hard_lock_and_regenerate_clears_it(ctx, mail):
    c, repo = ctx
    eid, doc, s, tok = _sent_email_code(c)
    rec = lambda: repo._docs[eid]["parsed"]["recipients"][0]                    # noqa: E731
    for i in range(esign.EC_HARD_LOCK):
        esign._RL.clear()
        rec().pop("ec_lock_until", None)
        if not rec().get("ec_hash"):
            rec()["ec_last_sent"] = "2000-01-01T00:00:00Z"
            assert c.post(f"/v1/sign/{tok}/email-code").status_code == 200
        r = c.post(f"/v1/sign/{tok}/email-code/verify", json={"code": "999999x"})
    assert r.status_code == 429 and r.json()["locked_until"] == "permanent"
    esign._RL.clear()
    rec()["ec_last_sent"] = "2000-01-01T00:00:00Z"
    assert c.post(f"/v1/sign/{tok}/email-code").status_code == 429
    owner = c.get(f"/v1/esign/envelopes/{eid}", headers=A).json()["recipients"][0]
    assert owner["email_code_locked"] is True
    c.post(f"/v1/esign/envelopes/{eid}/recipients/{s['id']}/regenerate", headers=A)
    tok2 = _tok(_links(c, eid)[1]["Sam Signer"]["link"])
    esign._RL.clear()
    assert c.post(f"/v1/sign/{tok2}/email-code").status_code == 200        # fresh link, fresh code state
    assert c.get(f"/v1/esign/envelopes/{eid}", headers=A).json()["recipients"][0]["email_code"] is True


def test_resend_gap_is_rounded_up_and_failed_sends_count(ctx, mail, monkeypatch):
    c, repo = ctx
    eid, doc, s, tok = _sent_email_code(c)
    assert c.post(f"/v1/sign/{tok}/email-code").status_code == 200
    rec = repo._docs[eid]["parsed"]["recipients"][0]
    # stored timestamps have whole seconds, so 58.x s elapsed leaves 1.x s: the reply must say >= 1, never 0
    rec["ec_last_sent"] = esign._iso(esign._now_dt() - dt.timedelta(seconds=58))
    r = c.post(f"/v1/sign/{tok}/email-code")
    assert r.status_code == 429 and r.json()["resend_in"] >= 1                 # never 0 while still refusing
    rec["ec_last_sent"] = "2000-01-01T00:00:00Z"

    def boom(*a):
        raise OSError("smtp down")
    monkeypatch.setattr(esign, "_send_mail", boom)
    esign._RL.clear()
    assert c.post(f"/v1/sign/{tok}/email-code").status_code == 502
    esign._RL.clear()
    assert c.post(f"/v1/sign/{tok}/email-code").status_code == 429             # the gap applies after a failure


def test_tsa_urls_are_shown_as_hosts_only(ctx, sealed_env, monkeypatch):
    monkeypatch.setenv("ESIGN_TSA_URLS", "https://user:secret@tsa.example.com/rfc3161?key=abc")
    c, _ = ctx
    cfg = c.get("/v1/esign/config", headers=A).json()
    assert cfg["seal"]["tsa"] == ["tsa.example.com"] and "secret" not in json.dumps(cfg)


# ------------------------------------------------------------------------------------------------- first-boot PKI
def test_first_boot_generates_a_seal_and_completed_pdfs_verify(ctx, monkeypatch, tmp_path, tsa):
    """No ESIGN_SEAL_P12: the server generates its own root + seal in DATA_DIR/pki (keys encrypted, files private),
    seals completed envelopes with it, and Verify recognises the result."""
    import os
    import stat
    from pyhanko.sign import timestamps
    from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper
    data = tmp_path / "boot"
    monkeypatch.setenv("ESIGN_DATA_DIR", str(data))
    monkeypatch.setenv("ESIGN_PKI_AUTO", "1")
    monkeypatch.setenv("ESIGN_BRAND_LEGAL_NAME", "Acme Legal Ltd")
    monkeypatch.setenv("ESIGN_TSA_URLS", "http://tsa.invalid/1")
    monkeypatch.setattr(timestamps, "HTTPTimeStamper",
                        lambda url, timeout=None, **kw: DummyTimeStamper(tsa_cert=tsa[0], tsa_key=tsa[1]))
    monkeypatch.setattr(K, "new_rsa", lambda bits=3072: K.rsa.generate_private_key(public_exponent=65537,
                                                                                    key_size=2048))
    p = esign.ensure_pki(data)
    assert p and p["seal_p12"].exists() and p["root"].exists()
    assert stat.S_IMODE(os.stat(p["dir"]).st_mode) == 0o700
    for f in ("pass", "root_key", "seal_p12"):
        assert stat.S_IMODE(os.stat(p[f]).st_mode) == 0o600
    assert b"ENCRYPTED" in p["root_key"].read_bytes()             # the root key is never stored in the clear
    assert K.ensure_pki(data)["seal_p12"].read_bytes() == p["seal_p12"].read_bytes()   # never regenerated
    c, _ = ctx
    eid, env, tok = _complete_one(c)
    seal = env["final"]["seal"]
    assert seal["sealed"] is True and seal["level"] == "PAdES-B-T"
    assert seal["cert_subject"].endswith("Acme Legal Ltd E-Sign Document Seal")
    final = _download(c, eid)
    ok = c.post("/v1/esign/verify", headers=A, files={"file": ("f.pdf", final, "application/pdf")}).json()
    assert ok["match"] and ok["seal"]["trusted"] and ok["seal"]["unchanged"]
    root = c.get("/v1/sign/root.crt")
    assert root.status_code == 200 and root.content == p["root"].read_bytes()
    assert "Acme-Legal-Ltd-E-Sign-Root-CA.crt" in root.headers["content-disposition"]


def test_pki_auto_off_means_unsealed_and_says_so(ctx, monkeypatch):
    monkeypatch.setenv("ESIGN_PKI_AUTO", "0")
    assert esign.ensure_pki() is None
    c, _ = ctx
    eid, env, tok = _complete_one(c)
    assert env["final"]["seal"] == {"sealed": False, "reason": "no seal certificate configured"}


def test_seal_p12_can_be_a_file_path(ctx, monkeypatch, pki, tmp_path, sealed_env):
    f = tmp_path / "seal.p12"
    f.write_bytes(pki["seal_p12"])
    monkeypatch.setenv("ESIGN_SEAL_P12", str(f))
    c, _ = ctx
    eid, env, tok = _complete_one(c)
    assert env["final"]["seal"]["sealed"] is True


def test_tsa_off_seals_without_a_timestamp(ctx, sealed_env, monkeypatch):
    monkeypatch.setenv("ESIGN_TSA_URLS", "off")
    c, _ = ctx
    eid, env, tok = _complete_one(c)
    assert env["final"]["seal"]["level"] == "PAdES-B-B" and sealed_env == []
