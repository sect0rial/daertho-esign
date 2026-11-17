"""E-Sign backend: envelopes, documents, recipients, fields, links, routing, signing, completion, audit trail.

Runs against a minimal FastAPI app that mounts only the esign router over an in-memory store (conftest.py), with
owner auth simulated by an X-Owner header (the real app wires auth.require_key).
Run: .venv/bin/pytest -q tests/test_esign.py
"""
import base64
import io
import os

import pytest

pytest.importorskip("reportlab")
pytest.importorskip("pypdfium2")

from fastapi import FastAPI, HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from PIL import Image, ImageDraw  # noqa: E402

from esign import esign, esign_pdf as P  # noqa: E402
from conftest import build_memory_repo  # noqa: E402


# ------------------------------------------------------------------------------------------------- fixtures
def _pdf(pages=2) -> bytes:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import A4
    b = io.BytesIO()
    c = canvas.Canvas(b, pagesize=A4)
    for i in range(pages):
        c.drawString(72, 760, f"Agreement page {i + 1}")
        c.showPage()
    c.save()
    return b.getvalue()


def _png_dataurl(w=300, h=90) -> str:
    im = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    ImageDraw.Draw(im).line([(10, h - 15), (w // 3, 15), (2 * w // 3, h - 15), (w - 10, 20)], fill=(20, 20, 70, 255), width=6)
    b = io.BytesIO()
    im.save(b, "PNG")
    return "data:image/png;base64," + base64.b64encode(b.getvalue()).decode()


@pytest.fixture
def ctx(monkeypatch):
    repo = build_memory_repo()

    def rk(request, key):
        o = request.headers.get("x-owner")
        if not o:
            raise HTTPException(status_code=401, detail="authentication required")
        return o

    esign.configure(lambda: repo, require_key=rk, session_label=lambda r: None)
    esign._RL.clear()
    app = FastAPI()
    app.include_router(esign.router)
    return TestClient(app), repo


A = {"x-owner": "alice"}
B = {"x-owner": "bob"}


def _new_env(c, title="MSA"):
    r = c.post("/v1/esign/envelopes", json={"title": title, "message": "Please sign"}, headers=A)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _upload(c, eid, data=None, name="msa.pdf", h=A):
    r = c.post(f"/v1/esign/envelopes/{eid}/documents", files={"file": (name, data or _pdf(), "application/pdf")}, headers=h)
    return r


def _setup_sequential(c):
    eid = _new_env(c)
    doc = _upload(c, eid).json()
    rs = c.put(f"/v1/esign/envelopes/{eid}/recipients", headers=A, json={"recipients": [
        {"name": "Ann Signer", "email": "ann@example.com", "role": "signer", "routing_order": 1},
        {"name": "Bob Second", "email": "bob@example.com", "role": "signer", "routing_order": 2},
        {"name": "Vic Viewer", "email": "vic@example.com", "role": "viewer", "routing_order": 2},
        {"name": "Cee Copy", "email": "cee@example.com", "role": "cc", "routing_order": 3},
    ]}).json()["recipients"]
    ann, bob, vic, cee = rs
    f = lambda rid, t, page, x, y, w=0.25, h=0.05, **kw: dict(recipient_id=rid, document_id=doc["id"], page=page, x=x, y=y, w=w, h=h, type=t, **kw)
    fields = [f(ann["id"], "signature", 1, 0.55, 0.80), f(ann["id"], "date_signed", 1, 0.55, 0.87, 0.15, 0.03),
              f(ann["id"], "name", 1, 0.10, 0.80, 0.25, 0.03), f(ann["id"], "checkbox", 1, 0.10, 0.70, 0.03, 0.02),
              f(bob["id"], "signature", 2, 0.55, 0.80), f(bob["id"], "initials", 2, 0.10, 0.90, 0.08, 0.04),
              f(bob["id"], "text", 2, 0.10, 0.80, 0.30, 0.03, label="Company number")]
    r = c.put(f"/v1/esign/envelopes/{eid}/fields", headers=A, json={"fields": fields})
    assert r.status_code == 200, r.text
    return eid, doc, ann, bob, vic, cee


def _links(c, eid):
    env = c.get(f"/v1/esign/envelopes/{eid}", headers=A).json()
    return env, {r["name"]: r for r in env["recipients"]}


def _tok(link):
    return link.split("/sign/")[1]


def _sign_fields(c, tok, extra_values=None, stamps=None):
    s = c.get(f"/v1/sign/{tok}/session").json()
    vals = {}
    for fl in s["fields"]:
        t = fl["type"]
        vals[fl["id"]] = {"signature": "adopted", "initials": "adopted", "checkbox": "true", "text": "C-12345",
                          "name": "Ann Signer"}.get(t, "")
    vals.update(extra_values or {})
    return c.post(f"/v1/sign/{tok}/complete", json={"values": vals, "signature": _png_dataurl(),
                                                     "initials": _png_dataurl(120, 70), "adopted_name": "Ann Signer",
                                                     "stamps": stamps or {}})


# ------------------------------------------------------------------------------------------------- tests
def test_create_get_list_and_isolation(ctx):
    c, _ = ctx
    eid = _new_env(c, "Lease")
    g = c.get(f"/v1/esign/envelopes/{eid}", headers=A).json()
    assert g["status"] == "draft" and g["title"] == "Lease" and g["integrity"]["ok"]
    assert any(e["id"] == eid for e in c.get("/v1/esign/envelopes", headers=A).json()["envelopes"])
    assert c.get(f"/v1/esign/envelopes/{eid}", headers=B).status_code == 404
    assert c.get("/v1/esign/envelopes", headers=B).json()["envelopes"] == []
    assert c.get("/v1/esign/envelopes").status_code == 401


def test_uploads_render_and_rejections(ctx):
    c, _ = ctx
    eid = _new_env(c)
    d = _upload(c, eid).json()
    assert d["page_count"] == 2 and len(d["sha256_original"]) == 64 and "blob_id" not in d
    im = Image.new("RGB", (800, 1000), "white")
    b = io.BytesIO()
    im.save(b, "PNG")
    d2 = _upload(c, eid, b.getvalue(), "scan.png").json()
    assert d2["page_count"] == 1 and d2["kind"] == "image"
    bad = _upload(c, eid, b"PK\x03\x04 not a pdf", "contract.docx")
    assert bad.status_code == 422 and "PDF" in bad.json()["detail"]
    r = c.get(f"/v1/esign/envelopes/{eid}/documents/{d['id']}/pages/1.png?scale=1", headers=A)
    assert r.status_code == 200 and r.headers["content-type"] == "image/png" and r.content[:4] == b"\x89PNG"
    r304 = c.get(f"/v1/esign/envelopes/{eid}/documents/{d['id']}/pages/1.png?scale=1", headers={**A, "If-None-Match": r.headers["etag"]})
    assert r304.status_code == 304
    assert c.get(f"/v1/esign/envelopes/{eid}/documents/{d['id']}/pages/9.png", headers=A).status_code == 404
    orig = c.get(f"/v1/esign/envelopes/{eid}/documents/{d2['id']}/file?which=original", headers=A)
    assert orig.status_code == 200 and orig.content[:4] == b"\x89PNG"
    # reorder + remove
    o = c.put(f"/v1/esign/envelopes/{eid}/documents/order", headers=A, json={"order": [d2["id"], d["id"]]}).json()
    assert [x["id"] for x in o["documents"]] == [d2["id"], d["id"]]
    assert c.delete(f"/v1/esign/envelopes/{eid}/documents/{d2['id']}", headers=A).json()["ok"]
    assert len(c.get(f"/v1/esign/envelopes/{eid}", headers=A).json()["documents"]) == 1


def test_recipient_and_field_validation(ctx):
    c, _ = ctx
    eid = _new_env(c)
    doc = _upload(c, eid).json()
    bad = c.put(f"/v1/esign/envelopes/{eid}/recipients", headers=A,
                json={"recipients": [{"name": "X", "email": "not-an-email", "role": "signer"}]})
    assert bad.status_code == 422
    rs = c.put(f"/v1/esign/envelopes/{eid}/recipients", headers=A, json={"recipients": [
        {"name": "S", "email": "s@example.com", "role": "signer"}, {"name": "C", "email": "c@example.com", "role": "cc"}]}).json()
    s, cc = rs["recipients"]
    assert s["color"] != cc["color"] and s["link"] is None and s["status"] == "created"
    for fld in ({"recipient_id": cc["id"], "type": "signature"},                       # cc can't own fields
                {"recipient_id": s["id"], "type": "signature", "x": 0.9, "w": 0.5, "page": 1, "y": 1.2},  # off page
                {"recipient_id": s["id"], "type": "signature", "page": 7},             # no such page
                {"recipient_id": s["id"], "type": "teleport"}):                          # bad type
        body = {"document_id": doc["id"], "page": 1, "x": 0.1, "y": 0.1, "w": 0.2, "h": 0.05, **fld}
        assert c.put(f"/v1/esign/envelopes/{eid}/fields", headers=A, json={"fields": [body]}).status_code == 422, fld
    # send without fields for the signer -> problems listed
    r = c.post(f"/v1/esign/envelopes/{eid}/send", headers=A)
    assert r.status_code == 422 and any("no fields" in p for p in r.json()["problems"])


def test_full_sequential_flow_completion_certificate_and_verify(ctx):
    c, repo = ctx
    eid, doc, ann, bob, vic, cee = _setup_sequential(c)
    sent = c.post(f"/v1/esign/envelopes/{eid}/send", headers=A)
    assert sent.status_code == 200, sent.text
    env, R = _links(c, eid)
    assert env["status"] == "sent" and env["current_order"] == 1
    assert R["Ann Signer"]["status"] == "sent" and R["Bob Second"]["status"] == "pending"
    assert R["Vic Viewer"]["status"] == "pending" and R["Cee Copy"]["status"] == "pending"
    assert all(r["link"].startswith("/sign/") for r in env["recipients"])
    ta, tb, tv, tc = (_tok(R[n]["link"]) for n in ("Ann Signer", "Bob Second", "Vic Viewer", "Cee Copy"))

    # Bob is not up yet; no document data leaks
    sb = c.get(f"/v1/sign/{tb}/session").json()
    assert sb["state"] == "waiting" and sb["documents"] == [] and sb["fields"] == []
    assert c.get(f"/v1/sign/{tb}/pages/{doc['id']}/1.png").status_code == 403

    # Ann: view -> must consent -> required fields enforced -> signs
    sa = c.get(f"/v1/sign/{ta}/session")
    assert sa.headers["x-frame-options"] == "DENY" and sa.headers["referrer-policy"] == "no-referrer"
    sa = sa.json()
    assert sa["state"] == "active" and len(sa["fields"]) == 4 and all(f["mine"] for f in sa["fields"])
    assert "bob@example.com" not in str(sa)                    # other recipients' emails never exposed
    assert c.get(f"/v1/sign/{ta}/pages/{doc['id']}/1.png").status_code == 200
    assert c.post(f"/v1/sign/{ta}/complete", json={"values": {}}).status_code == 409   # no consent yet
    assert c.post(f"/v1/sign/{ta}/consent").json()["recipient"]["consented"] is True
    sig_field = [f for f in sa["fields"] if f["type"] == "signature"][0]
    missing = c.post(f"/v1/sign/{ta}/complete", json={"values": {sig_field["id"]: "adopted"}, "signature": _png_dataurl()})
    assert missing.status_code == 422 and "required" in missing.json()["detail"]
    other = c.post(f"/v1/sign/{ta}/complete", json={"values": {"fld_0000000000": "x"}})
    assert other.status_code == 422
    done = _sign_fields(c, ta)
    assert done.status_code == 200, done.text and done.json()["state"] == "done"
    env, R = _links(c, eid)
    assert R["Ann Signer"]["status"] == "signed" and R["Ann Signer"]["first_viewed_at"]
    assert env["current_order"] == 2 and R["Bob Second"]["status"] == "sent" and R["Vic Viewer"]["status"] == "sent"
    assert R["Cee Copy"]["status"] == "pending"
    assert c.post(f"/v1/sign/{ta}/complete", json={}).status_code == 409    # can't sign twice

    # owner marks Bob's link shared, then regenerates it: the old link dies immediately
    assert c.post(f"/v1/esign/envelopes/{eid}/recipients/{bob['id']}/notified", headers=A).json()["status"] == "notified"
    newbob = c.post(f"/v1/esign/envelopes/{eid}/recipients/{bob['id']}/regenerate", headers=A).json()
    assert newbob["status"] == "sent" and newbob["link"] != R["Bob Second"]["link"]
    assert c.get(f"/v1/sign/{tb}/session").json()["state"] == "invalid"
    tb = _tok(newbob["link"])

    # Bob signs (page 2), the viewer acknowledges -> envelope completes
    assert c.post(f"/v1/sign/{tb}/consent").status_code == 200
    assert _sign_fields(c, tb).status_code == 200
    assert c.post(f"/v1/sign/{tv}/consent").status_code == 200
    vdone = c.post(f"/v1/sign/{tv}/complete", json={})
    assert vdone.status_code == 200 and vdone.json()["state"] == "completed"
    env, R = _links(c, eid)
    assert env["status"] == "completed" and env["completed_at"] and R["Cee Copy"]["status"] == "completed"
    assert env["final"]["sha256"] and env["integrity"]["ok"]
    evs = [e["event"] for e in env["events"]]
    for e in ("created", "sent", "link_generated", "viewed", "consented", "signed", "notified", "link_regenerated",
              "routing_advanced", "viewer_acknowledged", "completed", "sealed"):
        assert e in evs, e

    # cc downloads the final; it contains the 2 pages + certificate, and signatures are on the right pages
    dl = c.get(f"/v1/sign/{tc}/download")
    assert dl.status_code == 200 and dl.content[:4] == b"%PDF"
    assert P.page_count(dl.content) == 2 + env["final"]["cert_pages"]
    page1 = Image.open(io.BytesIO(P.render_page(dl.content, 0, 1.0))).convert("L")
    W, H = page1.size
    box = page1.crop((int(0.55 * W), int(0.80 * H), int(0.80 * W), int(0.85 * H)))
    assert sum(1 for v in box.getdata() if v < 128) > 20       # Ann's signature is stamped in her box
    own = c.get(f"/v1/esign/envelopes/{eid}/download?kind=combined", headers=A)
    assert own.status_code == 200 and P.sha256(own.content) == env["final"]["sha256"]
    cert = c.get(f"/v1/esign/envelopes/{eid}/download?kind=certificate", headers=A)
    assert cert.status_code == 200 and P.page_count(cert.content) == env["final"]["cert_pages"]

    # verify: final + original match, anything else doesn't
    vf = c.post("/v1/esign/verify", headers=A, files={"file": ("x.pdf", own.content, "application/pdf")}).json()
    assert vf["match"] and vf["kind"] == "final" and vf["envelope_id"] == eid
    vo = c.post("/v1/esign/verify", headers=A, files={"file": ("x.pdf", _pdf(), "application/pdf")}).json()
    assert vo["match"] is False or vo.get("kind") == "original"

    # tampering with the stored audit trail is detected
    repo._docs[eid]["parsed"]["events"][2]["actor"] = "someone-else"
    assert c.get(f"/v1/esign/envelopes/{eid}", headers=A).json()["integrity"]["ok"] is False


def test_decline_and_void(ctx):
    c, _ = ctx
    eid, doc, ann, bob, vic, cee = _setup_sequential(c)
    c.post(f"/v1/esign/envelopes/{eid}/send", headers=A)
    env, R = _links(c, eid)
    ta = _tok(R["Ann Signer"]["link"])
    assert c.post(f"/v1/sign/{ta}/decline", json={"reason": ""}).status_code == 422
    d = c.post(f"/v1/sign/{ta}/decline", json={"reason": "Wrong counterparty name"})
    assert d.status_code == 200 and d.json()["state"] == "declined"
    env, R = _links(c, eid)
    assert env["status"] == "declined" and env["decline"]["reason"] == "Wrong counterparty name"
    assert c.get(f"/v1/sign/{_tok(R['Bob Second']['link'])}/session").json()["state"] == "declined"
    assert [e["id"] for e in c.get("/v1/esign/envelopes?status=declined", headers=A).json()["envelopes"]] == [eid]
    # void
    eid2, *_ = _setup_sequential(c)
    c.post(f"/v1/esign/envelopes/{eid2}/send", headers=A)
    v = c.post(f"/v1/esign/envelopes/{eid2}/void", headers=A, json={"reason": "Superseded"}).json()
    assert v["status"] == "voided" and v["void_reason"] == "Superseded"
    t = _tok(next(r for r in _links(c, eid2)[0]["recipients"] if r["name"] == "Ann Signer")["link"] or "x/sign/x") \
        if _links(c, eid2)[0]["recipients"][0]["link"] else None
    assert t is None                                               # voided envelopes expose no links
    assert c.delete(f"/v1/esign/envelopes/{eid2}", headers=A).status_code == 409   # sent envelopes are records


def test_access_code_gate_and_lockout(ctx):
    c, repo = ctx
    eid = _new_env(c)
    doc = _upload(c, eid).json()
    s = c.put(f"/v1/esign/envelopes/{eid}/recipients", headers=A, json={"recipients": [
        {"name": "Sam", "email": "sam@example.com", "role": "signer", "access_code": "4321"}]}).json()["recipients"][0]
    assert s["access_code_set"] is True and "ac_hash" not in s and "4321" not in str(s)
    c.put(f"/v1/esign/envelopes/{eid}/fields", headers=A, json={"fields": [dict(recipient_id=s["id"], document_id=doc["id"], page=1, x=.5, y=.8, w=.25, h=.05, type="signature")]})
    c.post(f"/v1/esign/envelopes/{eid}/send", headers=A)
    tok = _tok(_links(c, eid)[1]["Sam"]["link"])
    g = c.get(f"/v1/sign/{tok}/session").json()
    assert g["state"] == "access_code" and g["documents"] == [] and g["recipient"]["email"] is None
    assert c.get(f"/v1/sign/{tok}/pages/{doc['id']}/1.png").status_code == 403
    for i in range(4):
        w = c.post(f"/v1/sign/{tok}/access", json={"code": "0000"})
        assert w.status_code == 401 and w.json()["attempts_left"] == 4 - i
    esign._RL.clear()
    lock = c.post(f"/v1/sign/{tok}/access", json={"code": "0000"})
    assert lock.status_code == 429 and lock.json()["locked_until"]
    assert c.post(f"/v1/sign/{tok}/access", json={"code": "4321"}).status_code == 429   # still locked
    for r in repo._docs[eid]["parsed"]["recipients"]:                                     # time passes
        r["ac_lock_until"] = "2000-01-01T00:00:00Z"
    ok = c.post(f"/v1/sign/{tok}/access", json={"code": "4321"})
    assert ok.status_code == 200 and any(k.startswith("esign_ac_") for k in ok.cookies.keys())
    assert c.get(f"/v1/sign/{tok}/session").json()["state"] == "active"
    assert c.get(f"/v1/sign/{tok}/pages/{doc['id']}/1.png").status_code == 200


def test_tokens_forgery_expiry_and_rate_limit(ctx):
    c, repo = ctx
    eid, doc, ann, *_ = _setup_sequential(c)
    c.post(f"/v1/esign/envelopes/{eid}/send", headers=A)
    tok = _tok(_links(c, eid)[1]["Ann Signer"]["link"])
    e, rid, v, mac = tok.split(".")
    for bad in (f"{e}.{rid}.{v}.{'0' * 32}", f"{e}.{rid}.{int(v) + 1}.{mac}", "garbage", f"{'f' * 32}.{rid}.{v}.{mac}"):
        assert c.get(f"/v1/sign/{bad}/session").json()["state"] == "invalid"
    # a different server secret invalidates links
    os.environ["ESIGN_SECRET"] = "rotated"
    try:
        assert c.get(f"/v1/sign/{tok}/session").json()["state"] == "invalid"
    finally:
        os.environ["ESIGN_SECRET"] = "test-secret"
    # expiry (lazy)
    repo._docs[eid]["parsed"]["expires_at"] = "2001-01-01T00:00:00Z"
    assert c.get(f"/v1/sign/{tok}/session").json()["state"] == "expired"
    assert c.get(f"/v1/esign/envelopes/{eid}", headers=A).json()["status"] == "expired"
    # rate limit on the public session endpoint
    esign._RL.clear()
    codes = [c.get(f"/v1/sign/{tok}/session").status_code for _ in range(62)]
    assert 429 in codes


def test_non_latin_text_needs_browser_stamp(ctx):
    c, _ = ctx
    eid = _new_env(c)
    doc = _upload(c, eid).json()
    s = c.put(f"/v1/esign/envelopes/{eid}/recipients", headers=A, json={"recipients": [
        {"name": "علي حسن", "email": "ali@example.ae", "role": "signer"}]}).json()["recipients"][0]
    fl = c.put(f"/v1/esign/envelopes/{eid}/fields", headers=A, json={"fields": [
        dict(recipient_id=s["id"], document_id=doc["id"], page=1, x=.1, y=.8, w=.3, h=.04, type="name")]}).json()["fields"][0]
    c.post(f"/v1/esign/envelopes/{eid}/send", headers=A)
    tok = _tok(_links(c, eid)[1]["علي حسن"]["link"])
    c.post(f"/v1/sign/{tok}/consent")
    r = c.post(f"/v1/sign/{tok}/complete", json={"values": {fl["id"]: "علي حسن"}})
    assert r.status_code == 422
    r = c.post(f"/v1/sign/{tok}/complete", json={"values": {fl["id"]: "علي حسن"}, "stamps": {fl["id"]: _png_dataurl(400, 60)}})
    assert r.status_code == 200 and r.json()["state"] == "completed"


def test_parallel_signers_duplicate_and_delete_rules(ctx):
    c, _ = ctx
    eid = _new_env(c)
    doc = _upload(c, eid).json()
    rs = c.put(f"/v1/esign/envelopes/{eid}/recipients", headers=A, json={"recipients": [
        {"name": "P1", "email": "p1@example.com", "role": "signer", "routing_order": 1, "access_code": "9999"},
        {"name": "P2", "email": "p2@example.com", "role": "signer", "routing_order": 1}]}).json()
    assert rs["signing_order"] == "parallel"
    p1, p2 = rs["recipients"]
    c.put(f"/v1/esign/envelopes/{eid}/fields", headers=A, json={"fields": [
        dict(recipient_id=p1["id"], document_id=doc["id"], page=1, x=.1, y=.8, w=.25, h=.05, type="signature"),
        dict(recipient_id=p2["id"], document_id=doc["id"], page=1, x=.6, y=.8, w=.25, h=.05, type="signature")]})
    c.post(f"/v1/esign/envelopes/{eid}/send", headers=A)
    env, R = _links(c, eid)
    assert R["P1"]["status"] == "sent" and R["P2"]["status"] == "sent"
    assert c.delete(f"/v1/esign/envelopes/{eid}", headers=A).status_code == 409   # sent: kept as a record
    dup = c.post(f"/v1/esign/envelopes/{eid}/duplicate", headers=A).json()
    assert dup["status"] == "draft" and dup["id"] != eid and dup["title"].endswith("(copy)")
    assert len(dup["documents"]) == 1 and len(dup["fields"]) == 2
    assert not any(r["access_code_set"] for r in dup["recipients"])
    assert {f["recipient_id"] for f in dup["fields"]} == {r["id"] for r in dup["recipients"]}
    assert c.get(f"/v1/esign/envelopes/{dup['id']}/documents/{dup['documents'][0]['id']}/pages/1.png", headers=A).status_code == 200
    assert c.delete(f"/v1/esign/envelopes/{dup['id']}", headers=A).json()["ok"]


def test_send_fails_closed_without_secret_in_production(ctx, monkeypatch):
    c, _ = ctx
    eid, *_ = _setup_sequential(c)
    monkeypatch.delenv("ESIGN_SECRET", raising=False)
    monkeypatch.setenv("ESIGN_ENV", "production")
    assert c.post(f"/v1/esign/envelopes/{eid}/send", headers=A).status_code == 503


def test_dev_without_secret_still_works_with_a_process_key(ctx, monkeypatch):
    c, _ = ctx
    monkeypatch.delenv("ESIGN_SECRET", raising=False)
    eid, *_ = _setup_sequential(c)
    assert c.post(f"/v1/esign/envelopes/{eid}/send", headers=A).status_code == 200
    tok = _tok(_links(c, eid)[1]["Ann Signer"]["link"])
    assert c.get(f"/v1/sign/{tok}/session").json()["state"] == "active"


# ------------------------------------------------------------------------------------------------- edge cases
def _sent_single(c, access_code=None, fields=None):
    eid = _new_env(c)
    doc = _upload(c, eid).json()
    rec = {"name": "Sam Signer", "email": "sam@example.com", "role": "signer"}
    if access_code:
        rec["access_code"] = access_code
    s = c.put(f"/v1/esign/envelopes/{eid}/recipients", headers=A, json={"recipients": [rec]}).json()["recipients"][0]
    fl = fields or [dict(type="signature", x=.5, y=.8, w=.25, h=.05)]
    c.put(f"/v1/esign/envelopes/{eid}/fields", headers=A, json={"fields": [dict(recipient_id=s["id"], document_id=doc["id"], page=1, **f) for f in fl]})
    assert c.post(f"/v1/esign/envelopes/{eid}/send", headers=A).status_code == 200
    return eid, doc, s, _tok(_links(c, eid)[1]["Sam Signer"]["link"])


def test_upload_rejects_oversized_pages_and_unstampable_pdfs(ctx):
    c, _ = ctx
    from reportlab.pdfgen import canvas
    b = io.BytesIO(); cv = canvas.Canvas(b, pagesize=(14400, 14400)); cv.drawString(10, 10, "x"); cv.showPage(); cv.save()
    eid = _new_env(c)
    r = _upload(c, eid, b.getvalue(), "huge.pdf")
    assert r.status_code == 422 and "unusual size" in r.json()["detail"]
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import DictionaryObject, NameObject
    w = PdfWriter(); w.append(PdfReader(io.BytesIO(_pdf(1))))
    w.pages[0][NameObject("/Contents")] = w._add_object(DictionaryObject())     # /Contents is not a stream
    o = io.BytesIO(); w.write(o)
    r2 = _upload(c, eid, o.getvalue(), "broken.pdf")
    # older pypdf releases can't stamp a page whose /Contents isn't a stream, so the upload's trial stamp rejects it;
    # current releases stamp it fine. Either way it must never be accepted and then fail at signing time.
    if r2.status_code == 200:
        fixed = P.flatten(P.normalize_upload(o.getvalue(), "broken.pdf", "application/pdf", max_pages=5)["pdf"],
                          [{"page": 1, "x": .1, "y": .1, "w": .3, "h": .05, "kind": "text", "text": "ok"}])
        assert P.page_count(fixed) == 1
    else:
        assert r2.status_code == 422, r2.text


def test_image_bombs_are_rejected_before_decoding(ctx):
    c, _ = ctx
    big = io.BytesIO(); Image.new("L", (9000, 9000), 255).save(big, "PNG", optimize=True)
    eid = _new_env(c)
    assert _upload(c, eid, big.getvalue(), "bomb.png").status_code == 422
    eid2, doc, s, tok = _sent_single(c)
    c.post(f"/v1/sign/{tok}/consent")
    bomb = io.BytesIO(); Image.new("L", (4000, 4000), 0).save(bomb, "PNG", optimize=True)
    durl = "data:image/png;base64," + base64.b64encode(bomb.getvalue()).decode()
    fid = c.get(f"/v1/sign/{tok}/session").json()["fields"][0]["id"]
    r = c.post(f"/v1/sign/{tok}/complete", json={"values": {fid: "adopted"}, "signature": durl})
    assert r.status_code == 422 and "too large" in r.json()["detail"]


def test_lifecycle_events_survive_a_full_noisy_trail(ctx, monkeypatch):
    c, _ = ctx
    monkeypatch.setattr(esign, "MAX_EVENTS", 15)
    monkeypatch.setattr(esign, "VIEW_EVENT_GAP", -1)                # every view/ok would log
    eid, doc, s, tok = _sent_single(c, access_code="2468")
    for _ in range(12):
        esign._RL.clear()
        assert c.post(f"/v1/sign/{tok}/access", json={"code": "2468"}).status_code == 200
    c.post(f"/v1/sign/{tok}/consent")
    assert _sign_fields(c, tok).status_code == 200
    evs = [e["event"] for e in c.get(f"/v1/esign/envelopes/{eid}", headers=A).json()["events"]]
    for e in ("consented", "signed", "completed", "sealed"):
        assert e in evs, e


def test_access_code_hard_lock_and_regenerate_clears_it(ctx):
    c, _ = ctx
    eid, doc, s, tok = _sent_single(c, access_code="2468")
    repo_env = None
    for i in range(esign.AC_HARD_LOCK):
        esign._RL.clear()
        for r in esign._repo().get_document_review(eid, None)["recipients"]:   # skip the 15-min waits
            r["ac_lock_until"] = None
        resp = c.post(f"/v1/sign/{tok}/access", json={"code": "0000"})
    assert resp.status_code == 429 and resp.json()["locked_until"] == "permanent"
    esign._RL.clear()
    assert c.post(f"/v1/sign/{tok}/access", json={"code": "2468"}).status_code == 429     # right code, still locked
    assert c.get(f"/v1/esign/envelopes/{eid}", headers=A).json()["recipients"][0]["access_locked"] is True
    new = c.post(f"/v1/esign/envelopes/{eid}/recipients/{s['id']}/regenerate", headers=A).json()
    assert new["access_locked"] is False
    assert c.post(f"/v1/sign/{_tok(new['link'])}/access", json={"code": "2468"}).status_code == 200


def test_correcting_email_issues_a_new_link_and_resets_evidence(ctx):
    c, _ = ctx
    eid, doc, s, tok = _sent_single(c)
    c.get(f"/v1/sign/{tok}/session"); c.post(f"/v1/sign/{tok}/consent")
    fixed = c.patch(f"/v1/esign/envelopes/{eid}/recipients/{s['id']}", headers=A, json={"email": "sam.real@example.com"}).json()
    assert fixed["link"] != "/sign/" + tok and fixed["view_count"] == 0 and fixed["consented_at"] is None
    assert c.get(f"/v1/sign/{tok}/session").json()["state"] == "invalid"
    assert c.get(f"/v1/sign/{_tok(fixed['link'])}/session").json()["recipient"]["consented"] is False


@pytest.mark.parametrize("trust,peer,h,expect", [
    # behind our own proxy: the hop the proxy wrote (the last), not the CF claim or a client-added left hop
    ("1", ("172.18.0.4", 50000), {"cf-connecting-ip": "203.0.113.99", "x-forwarded-for": "6.6.6.6, 198.51.100.7"},
     "198.51.100.7"),
    # not configured to trust a proxy: the TCP peer, whatever headers the client sends
    ("", ("203.0.113.9", 50000), {"cf-connecting-ip": "203.0.113.99", "x-forwarded-for": "198.51.100.7"},
     "203.0.113.9"),
    # an IPv6 signer: the full address on the evidence (only the rate limits count by its /64)
    ("1", ("172.18.0.4", 50000), {"x-forwarded-for": "2a01:4f8:c0c:1234::abcd"}, "2a01:4f8:c0c:1234::abcd"),
])
def test_signer_ip_ignores_client_supplied_headers(ctx, monkeypatch, trust, peer, h, expect):
    c0, _ = ctx
    monkeypatch.setenv("ESIGN_TRUST_PROXY", trust)
    eid, doc, s, tok = _sent_single(c0, fields=[dict(type="signature", x=.5, y=.8, w=.25, h=.05), dict(type="email", x=.1, y=.8, w=.3, h=.04)])
    n0 = len(c0.get(f"/v1/esign/envelopes/{eid}", headers=A).json()["events"])   # set-up events came from the test client
    c = TestClient(c0.app, client=peer)
    c.post(f"/v1/sign/{tok}/consent", headers=h)
    sess = c.get(f"/v1/sign/{tok}/session", headers=h).json()
    vals = {f["id"]: ("adopted" if f["type"] == "signature" else "attacker@evil.example") for f in sess["fields"]}
    assert c.post(f"/v1/sign/{tok}/complete", headers=h, json={"values": vals, "signature": _png_dataurl()}).status_code == 200
    env = c.get(f"/v1/esign/envelopes/{eid}", headers=A).json()
    r = env["recipients"][0]
    assert r["sign_ip"] == expect
    signer_ips = {e["ip"] for e in env["events"][n0:] if e.get("ip")}
    assert signer_ips == {expect}                                           # the audit trail agrees
    assert [f["value"] for f in env["fields"] if f["type"] == "email"] == ["sam@example.com"]   # never signer-typed


def test_expiry_blocks_pages_without_a_session_call_and_bad_tokens_are_clean(ctx):
    c, repo = ctx
    eid, doc, s, tok = _sent_single(c)
    repo._docs[eid]["parsed"]["expires_at"] = "2001-01-01T00:00:00Z"
    assert c.get(f"/v1/sign/{tok}/pages/{doc['id']}/1.png").status_code == 403
    for bad in ("%s.rcp_0123456789.\u0661.%s" % ("a" * 32, "b" * 32), "a" * 32 + ".rcp_0123456789.1." + "\u00e9" * 32):
        assert c.get(f"/v1/sign/{bad}/session").json()["state"] == "invalid"
    big = c.post(f"/v1/sign/{tok}/complete", content=b"x", headers={"content-length": str(50 * 1024 * 1024)})
    assert big.status_code == 413


def test_failed_completion_keeps_earlier_signatures_intact(ctx, monkeypatch):
    c, _ = ctx
    eid, doc, ann, bob, vic, cee = _setup_sequential(c)
    c.post(f"/v1/esign/envelopes/{eid}/send", headers=A)
    R = _links(c, eid)[1]
    ta, tb, tv = (_tok(R[n]["link"]) for n in ("Ann Signer", "Bob Second", "Vic Viewer"))
    c.post(f"/v1/sign/{ta}/consent"); assert _sign_fields(c, ta).status_code == 200
    c.post(f"/v1/sign/{tb}/consent"); assert _sign_fields(c, tb).status_code == 200
    c.post(f"/v1/sign/{tv}/consent")
    real = esign._certificate
    monkeypatch.setattr(esign, "_certificate", lambda env: (_ for _ in ()).throw(RuntimeError("boom")))
    from fastapi.testclient import TestClient as _TC
    bad = _TC(c.app, raise_server_exceptions=False).post(f"/v1/sign/{tv}/complete", json={})
    assert bad.status_code == 500
    monkeypatch.setattr(esign, "_certificate", real)
    ok = c.post(f"/v1/sign/{tv}/complete", json={})
    assert ok.status_code == 200 and ok.json()["state"] == "completed"
    final = c.get(f"/v1/esign/envelopes/{eid}/download", headers=A).content
    page1 = Image.open(io.BytesIO(P.render_page(final, 0, 1.0))).convert("L")
    W, H = page1.size
    box = page1.crop((int(0.55 * W), int(0.80 * H), int(0.80 * W), int(0.85 * H)))
    assert sum(1 for v in box.getdata() if v < 128) > 20                   # Ann's signature survived


# ------------------------------------------------------------------------------------------------- standalone product
def test_only_esign_env_vars_are_read():
    """Every setting the package reads is an ESIGN_* variable (documented in .env.example)."""
    import re
    from pathlib import Path
    pkg = Path(esign.__file__).resolve().parent
    pat = re.compile(r"""environ(?:\.get)?[\[(]\s*["']([A-Z0-9_]+)["']""")
    names = set()
    for f in sorted(pkg.rglob("*.py")):
        names |= set(pat.findall(f.read_text(encoding="utf-8")))
    assert names and all(n.startswith("ESIGN_") or n in ("PATH",) for n in names), sorted(names)


def test_identity_check_routes_are_not_shipped(ctx):
    c, _ = ctx
    paths = {getattr(r, "path", "") for r in esign.router.routes}
    assert not any("identity" in p or "/ades/" in p for p in paths)
    cfg = c.get("/v1/esign/config", headers=A).json()
    assert cfg["identity"]["available"] is False
    eid, *_ = _setup_sequential(c)
    rs = c.get(f"/v1/esign/envelopes/{eid}", headers=A).json()["recipients"]
    assert all("identity_check" not in r and "ades" not in r for r in rs)
