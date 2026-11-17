"""E-Sign email delivery: the server emails signing links, reminders, completed copies, void notices and notes to the
sender when the owner asks for it (notify) and the server can email (ESIGN_SMTP_HOST + ESIGN_MAIL=1); otherwise the
share-it-yourself flow sends no email of any kind.

Runs on the same minimal app as test_esign.py (in-memory repo, X-Owner auth). Delivery runs in the request's own
thread (esign.MAIL_SYNC) and esign._send_mail is replaced by a recorder, so nothing touches the network.
Run: .venv/bin/pytest -q tests/test_esign_mail.py
"""
import datetime as dt
import email.utils
import hashlib
import io
import re
import smtplib

import pytest

pytest.importorskip("reportlab")
pytest.importorskip("pypdfium2")

from fastapi.testclient import TestClient  # noqa: E402

from esign import esign  # noqa: E402
from test_esign import A, _sign_fields, _tok, _upload, ctx  # noqa: E402,F401

_REAL_SEND = esign._send_mail
TITLE = "Master Services Agreement"
FROM_ADDR = "hello@esign.example"
SENDER_EMAIL = "alice@owner.example"
SENDER = {"sender_name": "Alice Owner", "sender_email": SENDER_EMAIL}
CODE = "Kiwi-7319"                                                   # never a substring of a hex token
BASE = "http://testserver"


# ------------------------------------------------------------------------------------------------- fixtures
class Box:
    """Stands in for esign._send_mail: records each email, or raises what `fail` says (an exception, or a callable
    taking the To address and returning an exception or None)."""

    def __init__(self):
        self.sent = []
        self.fail = None

    def __call__(self, to, subject, body, attachments=None, reply_to=None, sender=None):
        exc = self.fail(to) if callable(self.fail) else self.fail
        if exc is not None:
            raise exc
        self.sent.append({"to": to, "subject": subject, "body": body, "attachments": list(attachments or []),
                          "reply_to": reply_to, "sender": sender})

    def to(self, addr):
        return [m for m in self.sent if m["to"] == addr]

    def clear(self):
        self.sent.clear()


def _reset_mail_state():
    esign._RL.clear()
    esign._MQ.clear()
    esign._MAIL_PENDING.clear()
    esign._MAIL_UNRECORDED.clear()
    esign._CAPS_REBUILT.clear()
    esign._MAIL_SCANNED[0] = 0.0


@pytest.fixture
def mail(ctx, monkeypatch):
    monkeypatch.setenv("ESIGN_SMTP_HOST", "smtp.invalid")
    monkeypatch.setenv("ESIGN_SMTP_FROM", f"Daertho E-Sign <{FROM_ADDR}>")
    monkeypatch.setenv("ESIGN_MAIL", "1")                             # opt-in per server
    for k in ("ESIGN_PUBLIC_URL", "ESIGN_SEAL_P12", "ESIGN_SMTP_PORT", "ESIGN_SMTP_USER"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(esign, "MAIL_SYNC", True)
    box = Box()
    monkeypatch.setattr(esign, "_send_mail", box)
    _reset_mail_state()
    yield box
    _reset_mail_state()


def _transient():
    return smtplib.SMTPServerDisconnected("Connection unexpectedly closed")


def _ago(seconds: float) -> str:
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _secs_until(iso: str) -> float:
    return (esign._parse_iso(iso) - dt.datetime.now(dt.timezone.utc)).total_seconds()


def _rec(repo, eid):
    """The stored envelope record (what a restart would read back)."""
    return repo._docs[eid]["parsed"]


def _srec(repo, eid, name):
    return next(r for r in _rec(repo, eid)["recipients"] if r["name"] == name)


def _view(c, eid, h=A):
    r = c.get(f"/v1/esign/envelopes/{eid}", headers=h)
    assert r.status_code == 200, r.text
    return r.json()


def _rv(c, eid, name, h=A):
    return next(r for r in _view(c, eid, h)["recipients"] if r["name"] == name)


def _link(c, eid, name, h=A, base=BASE):
    return base + _rv(c, eid, name, h)["link"]


def r_ok(resp):
    assert resp.status_code == 200, resp.text
    return True


def _new(c, h=A, title=TITLE, sender=True, **kw):
    body = {"title": title, "message": "Please sign by Friday."}
    if sender:
        body.update(SENDER)
    else:
        body["sender_name"] = "alice"                                # emailing needs a name, not an address
    body.update(kw)
    r = c.post("/v1/esign/envelopes", json=body, headers=h)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _setup(c, h=A, title=TITLE, sender=True, **kw):
    """Ann signs first; then Bob (access code), Cee (copy) and Vic (viewer) together at routing order 2."""
    eid = _new(c, h, title, sender, **kw)
    doc = _upload(c, eid, h=h).json()
    rs = c.put(f"/v1/esign/envelopes/{eid}/recipients", headers=h, json={"recipients": [
        {"name": "Ann Signer", "email": "ann@example.com", "role": "signer", "routing_order": 1},
        {"name": "Bob Second", "email": "bob@example.com", "role": "signer", "routing_order": 2, "access_code": CODE},
        {"name": "Cee Copy", "email": "cee@example.com", "role": "cc", "routing_order": 2},
        {"name": "Vic Viewer", "email": "vic@example.com", "role": "viewer", "routing_order": 2},
    ]})
    assert r_ok(rs)
    R = {r["name"]: r for r in rs.json()["recipients"]}
    f = lambda rid, page: dict(recipient_id=rid, document_id=doc["id"], page=page, x=.55, y=.8, w=.25, h=.05,  # noqa
                               type="signature")
    fr = c.put(f"/v1/esign/envelopes/{eid}/fields", headers=h,
               json={"fields": [f(R["Ann Signer"]["id"], 1), f(R["Bob Second"]["id"], 2)]})
    assert r_ok(fr)
    return eid, R


def _single(c, h=A, title=TITLE, sender=True, email="sam@example.com", access_code=None, **kw):
    eid = _new(c, h, title, sender, **kw)
    doc = _upload(c, eid, h=h).json()
    rec = {"name": "Sam Signer", "email": email, "role": "signer"}
    if access_code:
        rec["access_code"] = access_code
    rs = c.put(f"/v1/esign/envelopes/{eid}/recipients", headers=h, json={"recipients": [rec]})
    assert r_ok(rs)
    s = rs.json()["recipients"][0]
    fr = c.put(f"/v1/esign/envelopes/{eid}/fields", headers=h, json={"fields": [dict(
        recipient_id=s["id"], document_id=doc["id"], page=1, type="signature", x=.5, y=.8, w=.25, h=.05)]})
    assert r_ok(fr)
    return eid


def _send(c, eid, h=A, raw=False, **body):
    """Send asking the server to email the links (what the owner app does by default); raw=True posts no body at all."""
    if not raw:
        body.setdefault("notify", True)
    r = c.post(f"/v1/esign/envelopes/{eid}/send", headers=h, json=body) if body else \
        c.post(f"/v1/esign/envelopes/{eid}/send", headers=h)
    assert r.status_code == 200, r.text
    return r.json()


def _sign(c, link, code=None):
    tok = _tok(link)
    if code:
        assert c.post(f"/v1/sign/{tok}/access", json={"code": code}).status_code == 200
    assert c.post(f"/v1/sign/{tok}/consent").status_code == 200
    r = _sign_fields(c, tok)
    assert r.status_code == 200, r.text
    return r.json()


def _ack(c, link):
    tok = _tok(link)
    assert c.post(f"/v1/sign/{tok}/consent").status_code == 200
    r = c.post(f"/v1/sign/{tok}/complete", json={})
    assert r.status_code == 200, r.text
    return r.json()


def _events(repo, eid, kind=None):
    evs = _rec(repo, eid)["events"]
    return [e for e in evs if kind is None or e["event"] == kind]


def _cert_text(c, eid):
    from pypdf import PdfReader
    r = c.get(f"/v1/esign/envelopes/{eid}/download?kind=certificate", headers=A)
    assert r.status_code == 200
    return " ".join(" ".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(r.content)).pages).split())


def _next(c, eid, h=A):
    return next(e for e in c.get("/v1/esign/envelopes", headers=h).json()["envelopes"] if e["id"] == eid)["next_action"]


def _action_ids(c, h=A):
    return [e["id"] for e in c.get("/v1/esign/envelopes?status=action", headers=h).json()["envelopes"]]


# ------------------------------------------------------------------------------------------------- (2) first group
def test_send_emails_only_the_first_routing_group(ctx, mail):
    c, repo = ctx
    eid, R = _setup(c)
    assert _view(c, eid)["email_available"] is True
    v = _send(c, eid)
    assert v["mail"] == {"on": True, "base": BASE}
    assert [m["to"] for m in mail.sent] == ["ann@example.com"]
    m = mail.sent[0]
    ann = next(r for r in v["recipients"] if r["name"] == "Ann Signer")
    link = BASE + ann["link"]
    assert m["subject"] == f"Please sign: {TITLE}"
    assert link in m["body"] and re.findall(r"https?://\S+", m["body"]) == [link]
    assert "Please sign by Friday." in m["body"] and "Alice Owner" in m["body"]
    assert m["reply_to"] == SENDER_EMAIL
    assert m["sender"] == f"Alice Owner via Daertho E-Sign <{FROM_ADDR}>"
    assert m["attachments"] == []
    assert ann["status"] == "notified" and ann["link_emailed_at"] and ann["email_state"] == "sent"
    assert ann["email_count"] == 1 and ann["notified_at"]
    for n in ("Bob Second", "Cee Copy", "Vic Viewer"):
        r = next(x for x in v["recipients"] if x["name"] == n)
        assert r["status"] == "pending" and not r.get("email_state") and not r.get("link_emailed_at"), n
    ev = _events(repo, eid, "emailed")
    assert len(ev) == 1 and ev[0]["recipient_id"] == R["Ann Signer"]["id"] and ev[0]["actor"] == "system"
    assert ev[0]["detail"]["note"].startswith("signing link emailed to a") and "ann@example.com" not in str(ev)
    assert _rec(repo, eid)["outbox"] == [] and eid not in esign._MAIL_PENDING
    assert v["integrity"]["ok"] and _next(c, eid) == "Waiting for Ann Signer"
    assert eid not in _action_ids(c)
    assert "the links are emailed" in _events(repo, eid, "sent")[0]["detail"]["note"]
    s = c.get(f"/v1/sign/{_tok(link)}/session").json()
    assert s["state"] == "active" and s["envelope"]["emails_copy"] == "attach"


# ------------------------------------------------------------------------------------------------- (3) next group
def test_signer_one_signing_invites_group_two_and_notes_the_sender(ctx, mail):
    c, repo = ctx
    eid, R = _setup(c)
    _send(c, eid)
    mail.clear()
    _sign(c, _link(c, eid, "Ann Signer"))
    by = {m["to"]: m for m in mail.sent}
    assert sorted(by) == sorted(["bob@example.com", "cee@example.com", "vic@example.com", SENDER_EMAIL])
    assert by["bob@example.com"]["subject"] == f"Please sign: {TITLE}"
    assert by["vic@example.com"]["subject"] == f"Please review: {TITLE}"
    assert by["cee@example.com"]["subject"] == f"Alice Owner sent you a copy of “{TITLE}”"
    assert "You don't need to do anything" in by["cee@example.com"]["body"]
    for n in ("Bob Second", "Cee Copy", "Vic Viewer"):
        addr = n.split()[0].lower() + "@example.com"
        assert _link(c, eid, n) in by[addr]["body"], n
        r = _rv(c, eid, n)
        assert r["status"] == "notified" and r["email_state"] == "sent" and r["link_emailed_at"], n
    assert "access code" in by["bob@example.com"]["body"]
    assert all(CODE not in m["body"] and CODE not in m["subject"] for m in mail.sent)   # never the code itself
    note = by[SENDER_EMAIL]
    assert note["subject"] == f"Ann Signer signed “{TITLE}”"
    assert note["reply_to"] is None and note["sender"] == f"Daertho E-Sign <{FROM_ADDR}>" and note["attachments"] == []
    assert "1 of 3 people have finished" in note["body"] and "Waiting for: Bob Second, Vic Viewer." in note["body"]
    assert f"Open the envelope: {BASE}/#envelope/{eid}" in note["body"]
    assert "/sign/" not in note["body"]                                # the sender's note carries nobody's link
    assert _view(c, eid)["integrity"]["ok"]


def test_no_note_to_the_sender_without_a_sender_email(ctx, mail):
    c, repo = ctx
    eid, R = _setup(c, sender=False)
    _send(c, eid)
    mail.clear()
    _sign(c, _link(c, eid, "Ann Signer"))
    assert sorted(m["to"] for m in mail.sent) == ["bob@example.com", "cee@example.com", "vic@example.com"]
    assert all(m["reply_to"] is None for m in mail.sent)
    assert "Reply to this email" not in mail.sent[0]["body"] and "contact alice directly" in mail.sent[0]["body"]
    assert not any(j["kind"].startswith("owner_") for j in _rec(repo, eid).get("outbox") or [])


# ------------------------------------------------------------------------------------------------- (4) completion
def test_completion_emails_everyone_and_the_certificate_says_link_emailed(ctx, mail):
    c, repo = ctx
    eid, R = _setup(c)
    _send(c, eid)
    _sign(c, _link(c, eid, "Ann Signer"))
    _ack(c, _link(c, eid, "Vic Viewer"))                             # the viewer finishes before Bob
    bob_link = _link(c, eid, "Bob Second")
    mail.clear()
    assert _sign(c, bob_link, code=CODE)["state"] == "completed"    # Bob is the last one
    env = _view(c, eid)
    assert env["status"] == "completed"
    done = [m for m in mail.sent if m["subject"] == f"Completed: {TITLE}"]
    assert sorted(m["to"] for m in done) == sorted(["ann@example.com", "bob@example.com", "cee@example.com",
                                                     "vic@example.com", SENDER_EMAIL])
    assert len(mail.sent) == 5                                       # no owner_signed note for the last signer
    final = c.get(f"/v1/esign/envelopes/{eid}/download", headers=A).content
    for addr in ("ann@example.com", "cee@example.com", "vic@example.com"):
        m = mail.to(addr)[0]
        assert len(m["attachments"]) == 1, addr
        name, data, ctype = m["attachments"][0]
        assert name.endswith(".pdf") and ctype == "application/pdf" and data[:4] == b"%PDF"
        assert hashlib.sha256(data).hexdigest() == env["final"]["sha256"] == hashlib.sha256(final).hexdigest()
        assert "The signed PDF is attached" in m["body"] and m["reply_to"] == SENDER_EMAIL
    bob = mail.to("bob@example.com")[0]                              # access code: link only, never the file
    assert bob["attachments"] == [] and bob_link in bob["body"] and "Download the signed PDF" in bob["body"]
    owner = mail.to(SENDER_EMAIL)[0]
    assert owner["attachments"] == [] and "Everyone has signed" in owner["body"]
    notes = [e["detail"]["note"] for e in _events(repo, eid, "emailed")]
    assert sum("completed copy emailed" in n for n in notes) == 4
    assert sum("with the signed PDF attached" in n for n in notes) == 3
    assert _rec(repo, eid)["outbox"] == []
    text = _cert_text(c, eid)
    assert "Link emailed" in text and "Marked as shared" not in text
    assert env["integrity"]["ok"]


def test_sender_notes_over_a_whole_envelope(ctx, mail):
    c, repo = ctx
    eid, R = _setup(c)
    _send(c, eid)
    _sign(c, _link(c, eid, "Ann Signer"))
    _ack(c, _link(c, eid, "Vic Viewer"))
    _sign(c, _link(c, eid, "Bob Second"), code=CODE)
    assert [m["subject"] for m in mail.to(SENDER_EMAIL)] == [
        f"Ann Signer signed “{TITLE}”", f"Vic Viewer reviewed “{TITLE}”", f"Completed: {TITLE}"]
    assert "2 of 3 people have finished" in mail.to(SENDER_EMAIL)[1]["body"]


def test_large_final_pdf_is_linked_not_attached(ctx, mail, monkeypatch):
    c, repo = ctx
    monkeypatch.setattr(esign, "MAIL_ATTACH_MAX", 100)
    eid = _single(c)
    _send(c, eid)
    link = _link(c, eid, "Sam Signer")
    mail.clear()
    _sign(c, link)
    m = mail.to("sam@example.com")[0]
    assert m["subject"] == f"Completed: {TITLE}" and m["attachments"] == [] and link in m["body"]


# ------------------------------------------------------------------------------------------------- (5) notify false
def test_send_without_email_keeps_the_manual_share_flow(ctx, mail):
    c, repo = ctx
    eid, R = _setup(c)
    assert _view(c, eid)["email_available"] is True                  # it could have: the owner chose not to
    v = _send(c, eid, notify=False)
    assert mail.sent == [] and v["mail"] is None
    assert "mail" not in _rec(repo, eid) and not _rec(repo, eid).get("outbox")
    ann = _rv(c, eid, "Ann Signer")
    assert ann["status"] == "sent" and not ann.get("email_state") and not ann.get("link_emailed_at")
    assert _next(c, eid) == "Share link with Ann Signer" and eid in _action_ids(c)
    rem = c.post(f"/v1/esign/envelopes/{eid}/recipients/{R['Ann Signer']['id']}/remind", headers=A)
    assert rem.status_code == 409
    assert c.post(f"/v1/esign/envelopes/{eid}/recipients/{R['Ann Signer']['id']}/notified",
                  headers=A).json()["status"] == "notified"
    assert eid not in _action_ids(c)
    assert c.get(f"/v1/sign/{_tok(_link(c, eid, 'Ann Signer'))}/session").json()["envelope"]["emails_copy"] is False
    _sign(c, _link(c, eid, "Ann Signer"))
    assert mail.sent == []                                           # group 2 and the sender: still nothing
    assert eid in _action_ids(c) and _next(c, eid).startswith("Share link with Bob Second")   # by hand


# ------------------------------------------------------------------------------------------------- (6) failures
def test_transient_failure_is_retried_with_backoff_then_fails(ctx, mail):
    c, repo = ctx
    eid = _single(c)
    mail.fail = _transient()
    v = _send(c, eid)
    job = _rec(repo, eid)["outbox"]
    assert len(job) == 1 and job[0]["kind"] == "invite" and job[0]["tries"] == 1 and "sending" not in job[0]
    assert 55 <= _secs_until(job[0]["next"]) <= 61
    sam = next(r for r in v["recipients"] if r["name"] == "Sam Signer")
    assert sam["email_state"] == "queued" and sam["email_error"] == "the mail server didn't answer"
    assert sam["status"] == "sent" and not sam.get("link_emailed_at")
    assert _next(c, eid) == "Emailing Sam Signer" and eid not in _action_ids(c)
    assert eid in esign._MAIL_PENDING
    assert esign._deliver(eid, "alice") == 0 and _rec(repo, eid)["outbox"][0]["tries"] == 1   # not due yet
    for n in range(2, esign.MAIL_TRIES + 1):
        _rec(repo, eid)["outbox"][0]["next"] = _ago(1)
        assert esign._deliver(eid, "alice") == 0
        if n < esign.MAIL_TRIES:
            j = _rec(repo, eid)["outbox"][0]
            assert j["tries"] == n and abs(_secs_until(j["next"]) - esign.MAIL_BACKOFF[n - 1]) <= 5
            assert _srec(repo, eid, "Sam Signer")["email_state"] == "queued"
    sam = _srec(repo, eid, "Sam Signer")
    assert sam["email_state"] == "failed" and sam["email_error"] == "the mail server didn't answer"
    assert sam["email_failed_at"]
    fails = _events(repo, eid, "email_failed")
    assert len(fails) == 1 and "the link couldn't be emailed to s" in fails[0]["detail"]["note"]
    ob = _rec(repo, eid)["outbox"]                                    # the note to the sender was tried at once too
    assert [j["kind"] for j in ob] == ["owner_failed"] and ob[0]["tries"] == 1
    v = _view(c, eid)
    assert _next(c, eid) == "Couldn't email Sam Signer — share the link" and eid in _action_ids(c)
    assert v["integrity"]["ok"]
    mail.fail = None
    ob[0]["next"] = _ago(1)
    assert esign._deliver(eid, "alice") == 1
    note = mail.sent[-1]
    assert note["to"] == SENDER_EMAIL and note["subject"] == "We couldn't email Sam Signer"
    assert "the mail server didn't answer" in note["body"] and "/sign/" not in note["body"]
    assert _rec(repo, eid)["outbox"] == [] and eid not in esign._MAIL_PENDING


def test_transient_failure_then_recovery(ctx, mail):
    c, repo = ctx
    eid = _single(c)
    mail.fail = _transient()
    _send(c, eid)
    mail.fail = None
    _rec(repo, eid)["outbox"][0]["next"] = _ago(1)
    assert esign._deliver(eid, "alice") == 1
    sam = _rv(c, eid, "Sam Signer")
    assert sam["email_state"] == "sent" and not sam.get("email_error") and sam["status"] == "notified"
    assert sam["link_emailed_at"] and mail.sent[0]["to"] == "sam@example.com"
    assert _rec(repo, eid)["outbox"] == []


def test_permanent_failure_fails_at_once_and_email_again_works(ctx, mail):
    c, repo = ctx
    eid = _single(c)
    refused = smtplib.SMTPRecipientsRefused({"sam@example.com": (550, b"5.1.1 no such user")})
    mail.fail = lambda to: refused if to == "sam@example.com" else None
    v = _send(c, eid)
    sam = next(r for r in v["recipients"] if r["name"] == "Sam Signer")
    assert sam["email_state"] == "failed" and sam["email_error"] == "the mail server refused the address (550)"
    assert _rec(repo, eid)["outbox"] == []                            # the invite is not retried ...
    assert [m["subject"] for m in mail.to(SENDER_EMAIL)] == ["We couldn't email Sam Signer"]   # ... the sender hears
    assert len(_events(repo, eid, "email_failed")) == 1
    assert _next(c, eid) == "Couldn't email Sam Signer — share the link"
    # "Email again" (the remind endpoint) after a failed first email: an invitation, not a reminder
    mail.fail = None
    r = c.post(f"/v1/esign/envelopes/{eid}/recipients/{sam['id']}/remind", headers=A)
    assert r.status_code == 200, r.text
    assert r.json()["email_state"] == "sent" and r.json()["status"] == "notified"
    inv = mail.to("sam@example.com")
    assert len(inv) == 1 and inv[0]["subject"] == f"Please sign: {TITLE}"


@pytest.mark.parametrize("exc,permanent", [
    (smtplib.SMTPServerDisconnected("x"), False),
    (smtplib.SMTPResponseException(451, b"try later"), False),
    (smtplib.SMTPResponseException(550, b"no"), True),
    (smtplib.SMTPRecipientsRefused({"a@b.co": (550, b"no")}), True),
    (TimeoutError(), False),
    (OSError("connection refused"), False),
    (smtplib.SMTPRecipientsRefused({"a@b.co": (450, b"rate limited")}), False),
    (smtplib.SMTPRecipientsRefused({"a@b.co": (421, b"try again later")}), False),
    (ValueError("bad header"), False),                              # retried: rendering can hit a DB hiccup
])
def test_mail_reason_classifies_failures(exc, permanent):
    why, perm = esign._mail_reason(exc)
    assert perm is permanent and why and "\n" not in why


# ------------------------------------------------------------------------------------------------- (7) remind
def test_remind_gap_kind_and_who_can_be_reminded(ctx, mail, monkeypatch):
    c, repo = ctx
    eid, R = _setup(c)
    _send(c, eid)
    url = lambda n: f"/v1/esign/envelopes/{eid}/recipients/{R[n]['id']}/remind"   # noqa: E731
    first = mail.sent[0]
    mail.clear()
    soon = c.post(url("Ann Signer"), headers=A)
    assert soon.status_code == 429 and "few minutes ago" in soon.json()["detail"]
    for n in ("Bob Second", "Cee Copy"):                             # not their turn yet
        r = c.post(url(n), headers=A)
        assert r.status_code == 409 and "isn't their turn" in r.json()["detail"], n
    _srec(repo, eid, "Ann Signer")["emailed_at"] = _ago(esign.REMIND_GAP + 5)
    ok = c.post(url("Ann Signer"), headers=A)
    assert ok.status_code == 200, ok.text
    assert len(mail.sent) == 1 and mail.sent[0]["to"] == "ann@example.com"
    m = mail.sent[0]
    assert m["subject"] == f"Reminder: Please sign: {TITLE}" and "This is a reminder" in m["body"]
    assert _link(c, eid, "Ann Signer") in m["body"] and _link(c, eid, "Ann Signer") in first["body"]
    assert ok.json()["email_count"] == 2 and ok.json()["email_state"] == "sent"
    assert "reminder with the signing link emailed" in _events(repo, eid, "emailed")[-1]["detail"]["note"]
    assert c.post(url("Ann Signer"), headers=A).status_code == 429   # the gap applies again
    monkeypatch.setattr(esign, "REMIND_DAY", 1)                      # daily cap per recipient
    _srec(repo, eid, "Ann Signer")["emailed_at"] = _ago(esign.REMIND_GAP + 5)
    capped = c.post(url("Ann Signer"), headers=A)
    assert capped.status_code == 429 and "times today" in capped.json()["detail"]
    monkeypatch.setattr(esign, "REMIND_DAY", 5)
    _sign(c, _link(c, eid, "Ann Signer"))
    fin = c.post(url("Ann Signer"), headers=A)                       # finished
    assert fin.status_code == 409 and "still has to sign" in fin.json()["detail"]
    _srec(repo, eid, "Cee Copy")["emailed_at"] = _ago(esign.REMIND_GAP + 5)
    cc = c.post(url("Cee Copy"), headers=A)                          # a copy recipient has nothing to do
    assert cc.status_code == 409


def test_remind_refused_while_an_email_is_on_its_way(ctx, mail):
    c, repo = ctx
    eid = _single(c)
    _send(c, eid)
    s = _srec(repo, eid, "Sam Signer")
    s["email_state"], s["emailed_at"] = "queued", _ago(esign.REMIND_GAP + 5)
    r = c.post(f"/v1/esign/envelopes/{eid}/recipients/{s['id']}/remind", headers=A)
    assert r.status_code == 409 and "on its way" in r.json()["detail"]


# ------------------------------------------------------------------------------------------------- (8) regenerate
def test_regenerate_emails_the_new_link_unless_told_not_to(ctx, mail):
    c, repo = ctx
    eid = _single(c)
    _send(c, eid)
    old = _link(c, eid, "Sam Signer")
    rid = _rv(c, eid, "Sam Signer")["id"]
    mail.clear()
    r = c.post(f"/v1/esign/envelopes/{eid}/recipients/{rid}/regenerate", headers=A)
    assert r.status_code == 200, r.text
    new = BASE + r.json()["link"]
    assert new != old and len(mail.sent) == 1
    m = mail.sent[0]
    assert m["to"] == "sam@example.com" and m["subject"] == f"Please sign: {TITLE}"
    assert new in m["body"] and _tok(old) not in m["body"]
    assert r.json()["status"] == "notified" and r.json()["email_state"] == "sent"
    assert c.get(f"/v1/sign/{_tok(old)}/session").json()["state"] == "invalid"
    assert c.get(f"/v1/sign/{_tok(new)}/session").json()["state"] == "active"
    mail.clear()
    r2 = c.post(f"/v1/esign/envelopes/{eid}/recipients/{rid}/regenerate", headers=A, json={"notify": False})
    assert r2.status_code == 200 and BASE + r2.json()["link"] != new
    assert mail.sent == [] and not _rec(repo, eid)["outbox"]


def test_regenerate_replaces_a_queued_invite(ctx, mail):
    """A recipient never has two link emails waiting: the new link's invite replaces the unsent one."""
    c, repo = ctx
    eid = _single(c)
    mail.fail = _transient()
    _send(c, eid)
    rid = _srec(repo, eid, "Sam Signer")["id"]
    c.post(f"/v1/esign/envelopes/{eid}/recipients/{rid}/regenerate", headers=A)
    ob = _rec(repo, eid)["outbox"]
    assert [j["kind"] for j in ob] == ["invite"] and ob[0]["tries"] == 1   # the replacement failed once too
    mail.fail = None
    ob[0]["next"] = _ago(1)
    assert esign._deliver(eid, "alice") == 1
    assert len(mail.sent) == 1 and _link(c, eid, "Sam Signer") in mail.sent[0]["body"]


# ------------------------------------------------------------------------------------------------- (9) correct
def test_correcting_the_email_sends_the_new_link_to_the_new_address(ctx, mail):
    c, repo = ctx
    eid = _single(c)
    _send(c, eid)
    old = _link(c, eid, "Sam Signer")
    rid = _rv(c, eid, "Sam Signer")["id"]
    mail.clear()
    r = c.patch(f"/v1/esign/envelopes/{eid}/recipients/{rid}", headers=A, json={"email": "Sam.Real@Example.com"})
    assert r.status_code == 200, r.text
    new = BASE + r.json()["link"]
    assert [m["to"] for m in mail.sent] == ["sam.real@example.com"]
    assert new in mail.sent[0]["body"] and _tok(old) not in mail.sent[0]["body"]
    assert _events(repo, eid, "corrected")[-1]["detail"]["note"].endswith("the new link is being emailed")
    assert r.json()["email_state"] == "sent" and r.json()["status"] == "notified"
    mail.clear()
    r2 = c.patch(f"/v1/esign/envelopes/{eid}/recipients/{rid}", headers=A,
                 json={"email": "sam3@example.com", "notify": False})
    assert r2.status_code == 200 and mail.sent == []
    assert not _events(repo, eid, "corrected")[-1]["detail"]["note"].endswith("the new link is being emailed")


def test_correcting_a_recipient_whose_turn_has_not_come_sends_nothing_yet(ctx, mail):
    c, repo = ctx
    eid, R = _setup(c)
    _send(c, eid)
    mail.clear()
    r = c.patch(f"/v1/esign/envelopes/{eid}/recipients/{R['Bob Second']['id']}", headers=A,
                json={"email": "bob.real@example.com"})
    assert r.status_code == 200 and r.json()["status"] == "pending" and mail.sent == []
    _sign(c, _link(c, eid, "Ann Signer"))
    assert mail.to("bob.real@example.com") and not mail.to("bob@example.com")


# ------------------------------------------------------------------------------------------------- (10) void
def test_void_notifies_only_recipients_who_were_emailed(ctx, mail):
    c, repo = ctx
    eid, R = _setup(c)
    _send(c, eid)
    mail.clear()
    v = c.post(f"/v1/esign/envelopes/{eid}/void", headers=A, json={"reason": "Superseded by v2"})
    assert v.status_code == 200 and v.json()["status"] == "voided"
    assert [m["to"] for m in mail.sent] == ["ann@example.com"]       # Bob, Cee, Vic were never emailed
    m = mail.sent[0]
    assert m["subject"] == f"Voided: {TITLE}" and "Reason given: Superseded by v2" in m["body"]
    assert m["reply_to"] == SENDER_EMAIL and "/sign/" not in m["body"]
    assert "void notice emailed" in _events(repo, eid, "emailed")[-1]["detail"]["note"]
    assert _rec(repo, eid)["outbox"] == []


def test_void_without_a_reason_has_no_reason_line(ctx, mail):
    c, repo = ctx
    eid = _single(c)
    _send(c, eid)
    mail.clear()
    assert c.post(f"/v1/esign/envelopes/{eid}/void", headers=A, json={}).status_code == 200
    assert len(mail.sent) == 1 and "Reason given" not in mail.sent[0]["body"]


# ------------------------------------------------------------------------------------------------- (11) decline
def test_decline_notes_the_sender_and_no_recipient(ctx, mail):
    c, repo = ctx
    eid, R = _setup(c)
    _send(c, eid)
    mail.clear()
    d = c.post(f"/v1/sign/{_tok(_link(c, eid, 'Ann Signer'))}/decline", json={"reason": "Wrong entity name"})
    assert d.status_code == 200 and d.json()["state"] == "declined"
    assert [m["to"] for m in mail.sent] == [SENDER_EMAIL]
    m = mail.sent[0]
    assert m["subject"] == f"Ann Signer declined “{TITLE}”" and "Their reason is in the envelope" in m["body"]
    assert "Wrong entity name" not in m["body"] and "ann@example.com" not in m["body"]   # the address isn't verified
    assert _rec(repo, eid)["outbox"] == []


def test_decline_without_a_sender_email_sends_nothing(ctx, mail):
    c, repo = ctx
    eid = _single(c, sender=False)
    _send(c, eid)
    mail.clear()
    assert c.post(f"/v1/sign/{_tok(_link(c, eid, 'Sam Signer'))}/decline", json={"reason": "No"}).status_code == 200
    assert mail.sent == []


# ------------------------------------------------------------------------------------------------- (12) quota
def test_per_address_daily_limit_delays_the_email_instead_of_dropping_it(ctx, mail, monkeypatch):
    c, repo = ctx
    monkeypatch.setattr(esign, "MAIL_TO_DAY", 1)
    first = _single(c)
    _send(c, first)
    assert len(mail.to("sam@example.com")) == 1
    second = _single(c, title="Second agreement")
    v = _send(c, second)
    sam = next(r for r in v["recipients"] if r["name"] == "Sam Signer")
    assert sam["email_state"] == "queued" and sam["email_error"] == "this address has had today's limit of emails from you"
    assert len(mail.to("sam@example.com")) == 1                      # never handed to the mail server
    job = next(j for j in _rec(repo, second)["outbox"] if j["kind"] == "invite")
    assert job["tries"] == 0 and _secs_until(job["next"]) > 86000     # waits for the window, not counted as a try
    assert mail.to(SENDER_EMAIL) == []                                # nothing has failed: no note


def test_another_account_does_not_use_up_your_allowance_to_an_address(ctx, mail, monkeypatch):
    c, repo = ctx
    monkeypatch.setattr(esign, "MAIL_TO_DAY", 1)
    _send(c, _single(c))
    other = {"x-owner": "bob-firm"}
    v = _send(c, _single(c, h=other, title="Their agreement"), h=other)
    assert next(r for r in v["recipients"] if r["name"] == "Sam Signer")["email_state"] == "sent"
    assert len(mail.to("sam@example.com")) == 2


def test_account_daily_limit_waits_without_a_note_to_the_sender(ctx, mail, monkeypatch):
    c, repo = ctx
    monkeypatch.setattr(esign, "MAIL_OWNER_DAY", 1)
    _send(c, _single(c))
    second = _single(c, title="Second agreement", email="tom@example.com")
    v = _send(c, second)
    tom = next(r for r in v["recipients"] if r["name"] == "Sam Signer")
    assert tom["email_state"] == "queued" and tom["email_error"] == "the daily email limit for this account was reached"
    assert mail.to("tom@example.com") == [] and mail.to(SENDER_EMAIL) == []

# ------------------------------------------------------------------------------------------------- (13) expiry
def test_an_expired_envelope_drops_its_queued_invites(ctx, mail):
    c, repo = ctx
    eid = _single(c)
    mail.fail = _transient()
    _send(c, eid)
    rec = _rec(repo, eid)
    rec["expires_at"] = _ago(60)
    rec["outbox"][0]["next"] = _ago(1)
    mail.fail = None
    assert esign._deliver(eid, "alice") == 0
    assert mail.sent == []
    rec = _rec(repo, eid)
    assert rec["status"] == "expired" and rec["outbox"] == []
    assert _srec(repo, eid, "Sam Signer")["email_state"] is None    # no longer shown as queued
    assert eid not in esign._MAIL_PENDING


def test_invite_mentions_the_expiry(ctx, mail):
    c, repo = ctx
    eid = _single(c, expires_at="2099-03-04T05:06:00Z")
    _send(c, eid)
    assert "The link works until 4 Mar 2099, 05:06 UTC." in mail.sent[0]["body"]


# ------------------------------------------------------------------------------------------------- (14) headers
def test_title_and_sender_name_cannot_forge_headers(ctx, mail):
    c, repo = ctx
    eid = _single(c, title="Q3 deal\nBcc: victim@example.com", sender_name="Evil <ceo@bank.com>")
    _send(c, eid)
    m = mail.sent[0]
    assert "\n" not in m["subject"] and "\r" not in m["subject"]
    assert m["subject"] == "Please sign: Q3 deal Bcc: victim@example.com"
    snd = m["sender"]
    assert snd.count("<") == 1 and snd.endswith(f"<{FROM_ADDR}>")
    display = snd[:snd.index("<")]
    assert "@" not in display and ">" not in display and "Evil" in display
    assert email.utils.getaddresses([snd]) == [(email.utils.parseaddr(snd)[0], FROM_ADDR)]
    bad = c.patch(f"/v1/esign/envelopes/{eid}", headers=A, json={"sender_email": "a@b.co\nBcc: x@y.co"})
    assert bad.status_code == 422


def test_the_real_message_has_one_from_address_and_no_injected_headers(ctx, mail, monkeypatch):
    """The real _send_mail (with smtplib.SMTP faked) builds a message whose From is our address only."""
    sent_msgs = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=None, local_hostname=None):
            assert host == "smtp.invalid"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def ehlo(self):
            pass

        def has_extn(self, name):
            return False

        def starttls(self):
            raise AssertionError("no STARTTLS offered")

        def login(self, *a):
            raise AssertionError("no credentials configured")

        def send_message(self, msg):
            sent_msgs.append(msg)

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(esign, "_send_mail", _REAL_SEND)
    c, repo = ctx
    eid = _single(c, title="Q3 deal\r\nBcc: victim@example.com", sender_name='Evil "CEO" <ceo@bank.com>')
    v = _send(c, eid)
    assert next(r for r in v["recipients"])["email_state"] == "sent", v["recipients"]
    assert len(sent_msgs) == 1
    msg = sent_msgs[0]
    assert msg["To"] == "sam@example.com" and msg["Reply-To"] == SENDER_EMAIL
    assert msg.get_all("Bcc") is None and msg.get_all("Cc") is None
    froms = email.utils.getaddresses(msg.get_all("From"))
    assert len(froms) == 1 and froms[0][1] == FROM_ADDR and "@" not in froms[0][0]
    assert "\n" not in str(msg["Subject"])
    raw = msg.as_bytes()
    assert b"\nBcc:" not in raw and b"ceo@bank.com" not in raw.split(b"\n\n", 1)[0]
    assert msg["Message-ID"].endswith("@esign.example>") and msg["Date"]


# ------------------------------------------------------------------------------------------------- (15) owner view
def test_owner_view_hides_the_outbox_and_config_reports_email_links(ctx, mail, monkeypatch):
    c, repo = ctx
    eid = _single(c)
    draft = _view(c, eid)
    assert "mail_ok" not in draft and draft["email_available"] is True and draft["mail"] is None
    mail.fail = _transient()
    _send(c, eid)
    assert _rec(repo, eid)["outbox"]
    v = _view(c, eid)
    assert "outbox" not in v and "mail_ok" not in v and v["mail"]["on"] is True
    assert "outbox" not in str(v) and "ml_" not in str(v)                # no job ids either
    summary = c.get("/v1/esign/envelopes", headers=A).text
    assert "outbox" not in summary and "mail_ok" not in summary
    cfg = c.get("/v1/esign/config", headers=A).json()
    assert cfg["email_links"] is True and cfg.get("email_from", FROM_ADDR) == FROM_ADDR
    monkeypatch.setenv("ESIGN_MAIL", "0")
    cfg = c.get("/v1/esign/config", headers=A).json()
    assert cfg["email_links"] is False and cfg["email_codes"] is True and esign.mail_available() is False
    assert cfg.get("email_from") is None
    monkeypatch.delenv("ESIGN_MAIL")
    monkeypatch.delenv("ESIGN_SMTP_HOST")
    cfg = c.get("/v1/esign/config", headers=A).json()
    assert cfg["email_links"] is False and cfg["email_codes"] is False


def test_mail_switched_off_sends_without_email(ctx, mail, monkeypatch):
    c, repo = ctx
    monkeypatch.setenv("ESIGN_MAIL", "0")
    eid = _single(c)
    assert _view(c, eid)["email_available"] is False
    no = c.post(f"/v1/esign/envelopes/{eid}/send", headers=A, json={"notify": True})
    assert no.status_code == 422 and "no outgoing mail" in no.json()["detail"]
    v = _send(c, eid, raw=True)
    assert v["mail"] is None and mail.sent == [] and "mail" not in _rec(repo, eid)
    assert _next(c, eid) == "Share link with Sam Signer"
    assert esign.deliver_due() == 0


def test_no_smtp_means_no_email(ctx, mail, monkeypatch):
    c, repo = ctx
    monkeypatch.delenv("ESIGN_SMTP_HOST")
    eid = _single(c)
    assert _view(c, eid)["email_available"] is False
    v = _send(c, eid, raw=True)
    assert v["mail"] is None and mail.sent == []


# ------------------------------------------------------------------------------------------------- (16) restart
def test_delivery_loop_finds_queued_email_after_a_restart(ctx, mail):
    c, repo = ctx
    eid = _single(c)
    mail.fail = _transient()
    _send(c, eid)
    mail.fail = None
    _rec(repo, eid)["outbox"][0]["next"] = _ago(1)
    esign._MAIL_PENDING.clear()                                      # a restart: the in-memory index is gone
    import time as _t
    esign._MAIL_SCANNED[0] = _t.time()
    assert esign.deliver_due() == 0                                 # nothing known until the outboxes are re-read
    esign._MAIL_SCANNED[0] = 0.0
    assert esign.deliver_due() == 1
    assert [m["to"] for m in mail.sent] == ["sam@example.com"]
    assert esign._MAIL_SCANNED[0] > 0 and eid not in esign._MAIL_PENDING
    assert _rv(c, eid, "Sam Signer")["email_state"] == "sent"
    assert esign.deliver_due() == 0                                 # nothing sent twice


def test_a_send_lost_mid_way_is_retried_after_mail_stale(ctx, mail):
    c, repo = ctx
    eid = _single(c)
    mail.fail = _transient()
    _send(c, eid)
    mail.fail = None
    j = _rec(repo, eid)["outbox"][0]
    j["next"], j["sending"] = _ago(1), _ago(10)                      # another worker claimed it 10 s ago
    assert esign._deliver(eid, "alice") == 0 and mail.sent == []
    _rec(repo, eid)["outbox"][0]["sending"] = _ago(esign.MAIL_STALE + 5)   # ... and died
    assert esign._deliver(eid, "alice") == 1 and len(mail.sent) == 1


# ------------------------------------------------------------------------------------------------- (17) link base
def test_link_base_ignores_an_arbitrary_host(ctx, mail, monkeypatch):
    monkeypatch.setenv("ESIGN_PUBLIC_URL", "https://sign.example.org")
    c0, repo = ctx
    c = TestClient(c0.app, base_url="http://evil.example")
    eid = _single(c)
    v = _send(c, eid)
    assert v["mail"]["base"] == "https://sign.example.org"
    assert mail.sent[0]["body"].count("https://sign.example.org/sign/") == 1
    assert "evil.example" not in mail.sent[0]["body"]


def test_without_a_public_url_a_foreign_host_cannot_be_emailed(ctx, mail):
    c0, repo = ctx
    c = TestClient(c0.app, base_url="http://evil.example")
    eid = _single(c)
    r = c.post(f"/v1/esign/envelopes/{eid}/send", headers=A, json={"notify": True})
    assert r.status_code == 422 and "ESIGN_PUBLIC_URL" in r.json()["detail"]
    assert mail.sent == [] and _rec(repo, eid)["status"] == "draft"


def test_owner_link_and_signer_links_use_the_public_url(ctx, mail, monkeypatch):
    monkeypatch.setenv("ESIGN_PUBLIC_URL", "https://sign.example.org/")
    c, repo = ctx
    eid = _single(c)
    v = _send(c, eid)
    _sign(c, "https://sign.example.org" + next(r for r in v["recipients"])["link"])
    assert "https://sign.example.org/sign/" in mail.sent[0]["body"]
    owner_note = mail.to(SENDER_EMAIL)[-1]
    assert f"Open the envelope: https://sign.example.org/#envelope/{eid}" in owner_note["body"]


def test_link_base_follows_our_own_public_url(ctx, mail, monkeypatch):
    monkeypatch.setenv("ESIGN_PUBLIC_URL", "https://sign.example.org/")
    c0, repo = ctx
    c = TestClient(c0.app, base_url="https://sign.example.org")
    eid = _single(c)
    v = _send(c, eid)
    assert v["mail"]["base"] == "https://sign.example.org"
    link = "https://sign.example.org" + next(r for r in v["recipients"])["link"]
    assert link in mail.sent[0]["body"]


# ------------------------------------------------------------------------------------------------- suspected gaps
@pytest.mark.parametrize("how", ["correct", "regenerate"])
def test_link_emailed_time_belongs_to_the_current_link(ctx, mail, how):
    """The certificate's 'Link emailed' must date the email that carried the CURRENT link, not a retired one."""
    c, repo = ctx
    eid = _single(c)
    _send(c, eid)
    rid = _srec(repo, eid, "Sam Signer")["id"]
    stale = "2026-01-01T00:00:00Z"
    _srec(repo, eid, "Sam Signer")["link_emailed_at"] = stale        # the first link went out long ago
    if how == "correct":
        r = c.patch(f"/v1/esign/envelopes/{eid}/recipients/{rid}", headers=A, json={"email": "sam.real@example.com"})
    else:
        r = c.post(f"/v1/esign/envelopes/{eid}/recipients/{rid}/regenerate", headers=A)
    assert r.status_code == 200 and r.json()["email_state"] == "sent"
    assert r.json()["link_emailed_at"] != stale, (
        f"regression: after {how}, link_emailed_at still dates the retired link's email ({stale}); the "
        "certificate's 'Link emailed' then shows when an old link (possibly to the old address) was sent")


def test_regenerate_without_email_asks_the_owner_to_share(ctx, mail):
    """A new link the owner chose NOT to have emailed has gone to nobody: the owner must be told to share it."""
    c, repo = ctx
    eid = _single(c)
    _send(c, eid)
    rid = _srec(repo, eid, "Sam Signer")["id"]
    r = c.post(f"/v1/esign/envelopes/{eid}/recipients/{rid}/regenerate", headers=A, json={"notify": False})
    assert r.status_code == 200 and r.json()["status"] == "sent" and mail.sent[1:] == []
    nxt = _next(c, eid)
    assert nxt.startswith("Share link with") and eid in _action_ids(c), (
        f"regression: regenerate/correct with notify:false on an emailing envelope leaves the new link unshared "
        f"but next_action is {nxt!r} and the envelope is not in status=action (_needs_share only "
        f"flags email_state 'failed' once mail is on; email_state is still 'sent' from the OLD link)")


def test_mail_switched_off_mid_envelope_asks_the_owner_to_share(ctx, mail, monkeypatch):
    """ESIGN_MAIL=0 (or SMTP removed) after an emailing envelope was sent: the next group's links can't be
    emailed, so the owner must be prompted to share them, not shown 'Emailing …' forever."""
    c, repo = ctx
    eid, R = _setup(c)
    _send(c, eid)
    monkeypatch.setenv("ESIGN_MAIL", "0")
    _sign(c, _link(c, eid, "Ann Signer"))
    assert [m["to"] for m in mail.sent] == ["ann@example.com"]     # nothing more could go out
    nxt = _next(c, eid)
    assert "share" in nxt.lower(), (
        f"regression: with email switched off the queued invites never send and never fail, but next_action is "
        f"{nxt!r} and the remind endpoint answers 503 'copy the link and send it yourself'")


# ------------------------------------------------------------------------------------------------- edge cases
def test_send_without_notify_keeps_the_old_behaviour_for_existing_callers(ctx, mail):
    """API callers and owner tabs opened before the change post /send with no body: nobody is emailed."""
    c, repo = ctx
    eid = _single(c)
    v = _send(c, eid, raw=True)
    assert v["mail"] is None and mail.sent == [] and "mail" not in _rec(repo, eid)
    assert _next(c, eid) == "Share link with Sam Signer"


def test_emailing_needs_a_sender_name(ctx, mail):
    c, repo = ctx
    eid = _single(c, sender=False, sender_name="")
    r = c.post(f"/v1/esign/envelopes/{eid}/send", headers=A, json={"notify": True})
    assert r.status_code == 422 and any("Add your name" in p for p in r.json()["problems"])
    assert _rec(repo, eid)["status"] == "draft" and mail.sent == []


def test_email_is_opt_in_per_server(ctx, mail, monkeypatch):
    """A dev or staging copy with the same mail relay settings but without ESIGN_MAIL=1 never emails."""
    c, repo = ctx
    monkeypatch.delenv("ESIGN_MAIL")
    assert esign.smtp_configured() and not esign.mail_available()
    assert c.get("/v1/esign/config", headers=A).json()["email_links"] is False
    eid = _single(c)
    assert c.post(f"/v1/esign/envelopes/{eid}/send", headers=A, json={"notify": True}).status_code == 422
    assert esign.deliver_due() == 0 and mail.sent == []


def test_a_correction_during_a_failing_send_keeps_the_new_address_state(ctx, mail, repo_patch=None):
    """The link email to a mistyped address is refused while the owner corrects it: the refusal is history about the
    old address, not the state of the new one, and the sender isn't told the new address failed."""
    c, repo = ctx
    eid = _single(c, email="sam@typo.example")
    sid = _srec(repo, eid, "Sam Signer")["id"]

    def fail(to):
        if to == "sam@typo.example":
            r = next(x for x in _rec(repo, eid)["recipients"] if x["id"] == sid)
            r["email"], r["link_version"] = "sam@right.example", int(r.get("link_version") or 1) + 1
            return smtplib.SMTPRecipientsRefused({to: (550, b"no such user")})
        return None
    mail.fail = fail
    _send(c, eid)
    sam = _srec(repo, eid, "Sam Signer")
    assert sam.get("email_state") != "failed" and not sam.get("email_error")
    note = _events(repo, eid, "email_failed")[-1]["detail"]["note"]
    assert "s••@typo.example" in note and "since been replaced" in note
    assert not [j for j in _rec(repo, eid)["outbox"] if j["kind"] == "owner_failed"]
    assert mail.to(SENDER_EMAIL) == []


def test_an_in_flight_email_is_not_retried_next_to_its_replacement(ctx, mail):
    c, repo = ctx
    eid = _single(c)
    sid = _srec(repo, eid, "Sam Signer")["id"]
    calls = []

    def fail(to):
        calls.append(to)
        if len(calls) == 1:                                           # the owner presses "Email again" meanwhile
            esign._queue_mail(_rec(repo, eid), "remind", sid)
            return _transient()
        return None
    mail.fail = fail
    _send(c, eid)
    assert len(mail.to("sam@example.com")) == 1                      # the replacement only, once
    assert [j for j in _rec(repo, eid)["outbox"] if j.get("rid") == sid] == []


def test_voiding_while_an_invite_is_on_its_way_sends_the_void_notice(ctx, mail):
    c, repo = ctx
    eid = _single(c)

    def fail(to):
        if not mail.sent:
            _rec(repo, eid)["status"] = "voided"                      # voided while this email was being sent
            _rec(repo, eid)["void_reason"] = "Wrong version"
        return None
    mail.fail = fail
    _send(c, eid)
    assert [m["subject"] for m in mail.to("sam@example.com")] == [f"Please sign: {TITLE}", f"Voided: {TITLE}"]
    assert "Reason given: Wrong version" in mail.to("sam@example.com")[-1]["body"]


def test_a_database_hiccup_does_not_forget_queued_email(ctx, mail, monkeypatch):
    c, repo = ctx
    eid = _single(c)
    mail.fail = _transient()
    _send(c, eid)
    assert eid in esign._MAIL_PENDING
    real = esign._load
    monkeypatch.setattr(esign, "_load", lambda e, o=None: None)
    assert esign.deliver_due() == 0 and eid in esign._MAIL_PENDING   # still tracked
    monkeypatch.setattr(esign, "_load", real)
    mail.fail = None
    _rec(repo, eid)["outbox"][0]["next"] = _ago(1)
    assert esign.deliver_due() == 1 and len(mail.to("sam@example.com")) == 1


@pytest.mark.parametrize("addr", ["n1,victim@corp.example", "(1)victim@corp.example", "g:victim@corp.example;",
                                  "a@b@corp.example"])
def test_addresses_a_to_header_would_split_are_never_emailed(ctx, mail, addr):
    c, repo = ctx
    eid = _single(c, email=addr) if esign._EMAIL.match(addr) else None
    if eid is None:
        pytest.skip("rejected when the recipient is added")
    v = _send(c, eid)
    sam = next(r for r in v["recipients"] if r["name"] == "Sam Signer")
    assert sam["email_state"] == "failed" and "isn't one we can email" in sam["email_error"]
    assert [m["to"] for m in mail.sent] == [SENDER_EMAIL]             # only the note to the sender


def test_lookalike_and_filler_characters_cannot_disguise_the_sender(ctx, mail):
    c, repo = ctx
    eid = _single(c, sender_name="security＠paypal.com" + "⠀" * 40)
    _send(c, eid)
    sender = mail.sent[0]["sender"]
    name, addr = email.utils.parseaddr(sender)
    assert addr == FROM_ADDR and "@" not in name and "＠" not in name and "⠀" not in name
    assert name.endswith("via Daertho E-Sign")


def test_new_links_by_regenerate_have_a_daily_limit(ctx, mail, monkeypatch):
    c, repo = ctx
    monkeypatch.setattr(esign, "RELINK_DAY", 2)
    eid = _single(c)
    _send(c, eid)
    sid = _srec(repo, eid, "Sam Signer")["id"]
    for _ in range(2):
        assert c.post(f"/v1/esign/envelopes/{eid}/recipients/{sid}/regenerate", headers=A).status_code == 200
    third = c.post(f"/v1/esign/envelopes/{eid}/recipients/{sid}/regenerate", headers=A).json()
    assert third["email_note"] and third["email_state"] is None
    assert len(mail.to("sam@example.com")) == 3                      # the first link + two new ones, not a third
    assert _next(c, eid) == "Share link with Sam Signer" and eid in _action_ids(c)


def test_a_big_batch_goes_out_in_one_delivery(ctx, mail):
    c, repo = ctx
    eid = _new(c, A, TITLE, True)
    doc = _upload(c, eid).json()
    people = [{"name": f"Person {i}", "email": f"p{i}@example.com", "role": "signer"} for i in range(12)]
    rs = c.put(f"/v1/esign/envelopes/{eid}/recipients", headers=A, json={"recipients": people}).json()["recipients"]
    c.put(f"/v1/esign/envelopes/{eid}/fields", headers=A, json={"fields": [dict(
        recipient_id=r["id"], document_id=doc["id"], page=1, type="signature", x=.5, y=.8, w=.25, h=.05)
        for r in rs]})
    _send(c, eid)
    assert len(mail.sent) == 12 and _rec(repo, eid)["outbox"] == []


def test_link_base_ignores_userinfo_tricks(monkeypatch):
    from starlette.requests import Request as SR
    monkeypatch.delenv("ESIGN_PUBLIC_URL", raising=False)

    def req(host):
        return SR({"type": "http", "scheme": "http", "server": ("x", 80), "path": "/", "query_string": b"",
                   "headers": [(b"host", host.encode())]})
    assert esign._link_base(req("localhost:@evil.example"), "alice") == ""
    assert esign._link_base(req("localhost:8772"), "alice") == "http://localhost:8772"


def test_the_signer_page_says_how_the_copy_will_come(ctx, mail):
    c, repo = ctx
    eid, R = _setup(c)
    _send(c, eid)
    _sign(c, _link(c, eid, "Ann Signer"))
    assert c.get(f"/v1/sign/{_tok(_link(c, eid, 'Ann Signer'))}/session").json()["envelope"]["emails_copy"] == "attach"
    tok = _tok(_link(c, eid, "Bob Second"))
    c.post(f"/v1/sign/{tok}/access", json={"code": CODE})
    assert c.get(f"/v1/sign/{tok}/session").json()["envelope"]["emails_copy"] == "link"


def test_notes_to_the_sender_mask_recipient_addresses(ctx, mail):
    c, repo = ctx
    eid, R = _setup(c)
    _send(c, eid)
    mail.clear()
    _sign(c, _link(c, eid, "Ann Signer"))
    note = mail.to(SENDER_EMAIL)[0]
    assert "ann@example.com" not in note["body"] and "a••@example.com" in note["body"]


# ------------------------------------------------------------------------------------------------- edge cases
def test_failed_attempts_do_not_use_up_the_daily_caps(ctx, mail):
    c, repo = ctx
    eid = _single(c)
    mail.fail = _transient()
    _send(c, eid)
    assert not esign._MQ.get("esm-owner:alice") and not esign._MQ.get("esm-global")
    mail.fail = None
    _rec(repo, eid)["outbox"][0]["next"] = _ago(1)
    esign._deliver(eid, "alice")
    assert len(esign._MQ["esm-owner:alice"]) == 1


def test_encoded_words_stay_literal_text(ctx, mail):
    c, repo = ctx
    enc = "=?utf-8?b?c3VwcG9ydO+8oHBheXBhbC5jb20=?="                   # 'support＠paypal.com'
    eid = _single(c, sender_name=enc, title=enc)
    _send(c, eid)
    m = mail.sent[0]
    assert "=?" not in m["sender"] and "=?" not in m["subject"]
    real = esign._send_mail
    assert real is not _REAL_SEND                                     # (the recorder is in place)
    assert not esign._mailable("=?utf-8?b?dmljdGltQGV2aWwuY29t?=@x.example")
    r = c.post("/v1/esign/envelopes", headers=A, json={"title": "x", "sender_email": "=?utf-8?q?a?=@x.example"})
    assert r.status_code == 422


def test_one_note_lists_everyone_who_could_not_be_emailed(ctx, mail):
    c, repo = ctx
    eid, R = _setup(c)
    _send(c, eid)
    mail.clear()
    mail.fail = lambda to: smtplib.SMTPRecipientsRefused({to: (550, b"no")}) if to != SENDER_EMAIL else None
    _sign(c, _link(c, eid, "Ann Signer"))
    notes = mail.to(SENDER_EMAIL)
    assert [n["subject"] for n in notes if n["subject"].startswith("We couldn't")] == ["We couldn't email 3 recipients"]
    body = next(n for n in notes if n["subject"].startswith("We couldn't"))["body"]
    assert "Bob Second" in body and "Cee Copy" in body and "Vic Viewer" in body and "bob@example.com" not in body


def test_failure_notes_per_envelope_are_capped(ctx, mail, monkeypatch):
    c, repo = ctx
    monkeypatch.setattr(esign, "MAIL_FAILNOTE_DAY", 1)
    eid = _single(c)
    mail.fail = lambda to: smtplib.SMTPRecipientsRefused({to: (550, b"no")}) if to != SENDER_EMAIL else None
    _send(c, eid)
    sid = _srec(repo, eid, "Sam Signer")["id"]
    _rec(repo, eid)["recipients"][0]["emailed_at"] = None
    assert c.post(f"/v1/esign/envelopes/{eid}/recipients/{sid}/remind", headers=A).status_code == 200
    assert len([m for m in mail.to(SENDER_EMAIL) if m["subject"].startswith("We couldn't")]) == 1


def test_plus_tags_share_one_inbox_allowance(ctx, mail, monkeypatch):
    c, repo = ctx
    monkeypatch.setattr(esign, "MAIL_TO_DAY", 1)
    _send(c, _single(c, email="victim+1@example.com"))
    v = _send(c, _single(c, title="Again", email="victim+2@example.com"))
    assert next(r for r in v["recipients"])["email_state"] == "queued"
    assert esign._mailbox_key("V.I.C.Tim+x@googlemail.com") == "victim@gmail.com"


def test_a_retry_that_succeeds_drops_the_queued_repeat(ctx, mail):
    c, repo = ctx
    eid = _single(c)
    sid = _srec(repo, eid, "Sam Signer")["id"]
    first = []

    def fail(to):
        if not first:
            first.append(1)
            esign._queue_mail(_rec(repo, eid), "remind", sid)          # "Email again" while the retry is in flight
        return None
    mail.fail = fail
    _send(c, eid)
    esign._deliver(eid, "alice")
    assert len(mail.to("sam@example.com")) == 1
    assert not [j for j in _rec(repo, eid)["outbox"] if j.get("rid") == sid]


def test_results_a_database_error_kept_back_are_applied_without_resending(ctx, mail, monkeypatch):
    c, repo = ctx
    eid = _single(c)
    real_save, calls = esign._save, []

    def flaky(env):
        calls.append(1)
        if len(calls) == 3:                                          # phase 3 of the first delivery
            raise RuntimeError("db down")
        return real_save(env)
    monkeypatch.setattr(esign, "_save", flaky)
    r = c.post(f"/v1/esign/envelopes/{eid}/send", headers=A, json={"notify": True})
    assert r.status_code == 200
    assert len(mail.to("sam@example.com")) == 1 and eid in esign._MAIL_UNRECORDED
    monkeypatch.setattr(esign, "_save", real_save)
    for j in _rec(repo, eid)["outbox"]:
        j["sending"] = _ago(esign.MAIL_STALE + 5)                    # it would look lost by now
    esign._deliver(eid, "alice")
    assert len(mail.to("sam@example.com")) == 1                      # recorded, not re-sent
    assert _srec(repo, eid, "Sam Signer")["email_state"] == "sent" and eid not in esign._MAIL_UNRECORDED


def test_email_again_right_after_a_failure_is_allowed(ctx, mail):
    c, repo = ctx
    eid = _single(c)
    _send(c, eid)
    sid = _srec(repo, eid, "Sam Signer")["id"]
    mail.fail = lambda to: smtplib.SMTPRecipientsRefused({to: (550, b"no")}) if to == "sam@example.com" else None
    c.post(f"/v1/esign/envelopes/{eid}/recipients/{sid}/regenerate", headers=A)
    assert _srec(repo, eid, "Sam Signer")["email_state"] == "failed"
    mail.fail = None
    r = c.post(f"/v1/esign/envelopes/{eid}/recipients/{sid}/remind", headers=A)
    assert r.status_code == 200 and r.json()["email_state"] == "sent"


def test_a_scan_that_found_nothing_is_tried_again(ctx, mail, monkeypatch):
    c, repo = ctx
    monkeypatch.setattr(repo, "list_pipeline_owners", lambda p: [])
    esign.deliver_due()
    assert esign._MAIL_SCANNED[0] == 0.0


# ------------------------------------------------------------------------------------------------- edge cases
def test_a_failure_fixed_by_hand_is_not_listed_again(ctx, mail):
    c, repo = ctx
    eid, R = _setup(c)
    refuse = {"ann@example.com"}
    mail.fail = lambda to: smtplib.SMTPRecipientsRefused({to: (550, b"no")}) if to in refuse else None
    _send(c, eid)
    ann = R["Ann Signer"]["id"]
    assert c.post(f"/v1/esign/envelopes/{eid}/recipients/{ann}/notified", headers=A).status_code == 200
    refuse.add("bob@example.com")
    _sign(c, _link(c, eid, "Ann Signer"))
    second = [m for m in mail.to(SENDER_EMAIL) if m["subject"].startswith("We couldn't")][-1]
    assert second["subject"] == "We couldn't email Bob Second" and "Ann Signer" not in second["body"]


def test_list_rows_show_a_limit_held_recipient_as_one_to_share(ctx, mail, monkeypatch):
    c, repo = ctx
    monkeypatch.setattr(esign, "MAIL_TO_DAY", 1)
    _send(c, _single(c))
    second = _single(c, title="Second agreement")
    _send(c, second)
    row = next(e for e in c.get("/v1/esign/envelopes", headers=A).json()["envelopes"] if e["id"] == second)
    assert row["recipients"][0]["email_held"] is True and row["next_action"] == "Share link with Sam Signer"


# ------------------------------------------------------------------------------------------------- wording
@pytest.mark.parametrize("name,want", [("Maria Georgiou", "Maria"), ("Maria", "Maria"), ("  Maria   Anna Georgiou ", "Maria"),
                                       ("Dr Maria Georgiou", "Dr Georgiou"), ("Prof. Georgiou", "Prof. Georgiou"),
                                       ("Georgiou, Maria", "Maria"), ("Maria Georgiou, PhD", "Maria"), ("Dr", "Dr"),
                                       ("", ""), ("王伟", "王伟")])
def test_the_greeting_uses_the_first_name(name, want):
    assert esign._greeting_name(name) == want


def test_emails_greet_by_first_name_and_show_the_message_as_written(ctx, mail):
    c, repo = ctx
    eid = _new(c, A, TITLE, True, message="First paragraph that is long.\n\nThanks,\nAlice")
    doc = _upload(c, eid).json()
    rs = c.put(f"/v1/esign/envelopes/{eid}/recipients", headers=A, json={"recipients": [
        {"name": "Sam Signer", "email": "sam@example.com", "role": "signer", "note": "Page two matters."}]}).json()
    s = rs["recipients"][0]
    c.put(f"/v1/esign/envelopes/{eid}/fields", headers=A, json={"fields": [dict(
        recipient_id=s["id"], document_id=doc["id"], page=1, type="signature", x=.5, y=.8, w=.25, h=.05)]})
    _send(c, eid)
    body = mail.to("sam@example.com")[0]["body"]
    assert body.startswith("Hello Sam,\n") and "Sam Signer" not in body
    assert "Message from Alice Owner:\nFirst paragraph that is long.\n\nThanks,\nAlice\n" in body
    assert "A note for you:\nPage two matters.\n" in body


def test_notes_to_the_sender_carry_no_utc_time(ctx, mail):
    c, repo = ctx
    eid, R = _setup(c)
    _send(c, eid)
    _sign(c, _link(c, eid, "Ann Signer"))
    note = mail.to(SENDER_EMAIL)[0]
    assert "UTC" not in note["body"] and f"signed “{TITLE}”.\n" in note["body"]


@pytest.mark.parametrize("title,want", [
    ("Services Agreement — Acme × Globex", "Services Agreement — Acme × Globex - signed.pdf"),
    ("Contrat é/ñ: v2?", "Contrat é ñ v2 - signed.pdf"),
    ("..\\..\\evil‮gnp.exe", "evilgnp.exe - signed.pdf"),
    ("", "document - signed.pdf")])
def test_the_attachment_keeps_the_titles_symbols(title, want):
    got = esign._mail_filename(title)
    assert got == want if "evil" not in title else got.endswith("evilgnp.exe - signed.pdf") and "/" not in got
    assert "\\" not in got and "‮" not in got


def test_a_symbol_in_the_filename_survives_the_real_email(monkeypatch):
    """Through the real _send_mail: a mail client reads the same name back."""
    from email import message_from_bytes, policy
    grabbed = []

    class Fake:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def ehlo(self, *a):
            pass

        def has_extn(self, x):
            return False

        def send_message(self, m):
            grabbed.append(bytes(m))
    monkeypatch.setenv("ESIGN_SMTP_HOST", "smtp.invalid")
    monkeypatch.setattr(smtplib, "SMTP", Fake)
    name = esign._mail_filename("Services Agreement — Acme × Globex")
    _REAL_SEND("a@example.com", "s", "b", attachments=[(name, b"%PDF-1.4", "application/pdf")], sender="x <x@example.com>")
    part = next(message_from_bytes(grabbed[0], policy=policy.default).iter_attachments())
    assert part.get_filename() == "Services Agreement — Acme × Globex - signed.pdf"
