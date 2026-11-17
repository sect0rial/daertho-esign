"""The standalone shell: first-run setup, sign-in, users, API keys, branding, health, CSRF guard, store."""
import importlib
import os
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    monkeypatch.setenv("ESIGN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ESIGN_SECRET", "t" * 64)
    monkeypatch.setenv("ESIGN_TSA_URLS", "off")
    monkeypatch.delenv("ESIGN_DATABASE_URL", raising=False)
    monkeypatch.setenv("ESIGN_BRAND_NAME", "Acme Sign")
    monkeypatch.setenv("ESIGN_BRAND_ACCENT", "#ff0066")
    for m in [m for m in sys.modules if m == "esign.main"]:
        del sys.modules[m]
    main = importlib.import_module("esign.main")
    return TestClient(main.app, base_url="http://testserver")


def _setup(c, email="admin@example.com", pw="correct horse battery"):
    r = c.post("/v1/auth/setup", json={"email": email, "password": pw, "name": "Ada"})
    assert r.status_code == 200, r.text
    return r.json()["user"]


def test_health_and_brand(app_client):
    c = app_client
    assert c.get("/healthz").json()["ok"] is True
    b = c.get("/v1/brand").json()
    assert b["name"] == "Acme Sign" and b["accent"] == "#ff0066" and b["powered_by"] is True
    css = c.get("/brand.css").text
    assert "--brand-accent:#ff0066" in css and "fonts.googleapis.com" in css


def test_brand_rejects_unsafe_values(monkeypatch):
    from esign import brand
    monkeypatch.setenv("ESIGN_BRAND_ACCENT", "red;}body{display:none")
    monkeypatch.setenv("ESIGN_BRAND_FONT_HEAD", "x');@import url(evil")
    monkeypatch.setenv("ESIGN_BRAND_LOGO_URL", "javascript:alert(1)")
    d = brand.as_dict()
    assert d["accent"] == brand.DEFAULTS["accent"]
    assert d["font_head"] == brand.DEFAULTS["font_head"]
    assert d["logo_url"] == ""


def test_first_run_setup_then_locked(app_client):
    c = app_client
    assert c.get("/v1/auth/me").json() == {"user": None, "setup_needed": True}
    u = _setup(c)
    assert u["role"] == "admin"
    me = c.get("/v1/auth/me").json()
    assert me["user"]["email"] == "admin@example.com" and me["setup_needed"] is False
    r = c.post("/v1/auth/setup", json={"email": "x@example.com", "password": "another long pw"})
    assert r.status_code == 409


def test_login_logout_and_wrong_password(app_client):
    c = app_client
    _setup(c)
    c.post("/v1/auth/logout")
    assert c.get("/v1/auth/me").json()["user"] is None
    assert c.post("/v1/auth/login", json={"email": "admin@example.com", "password": "nope nope nope"}).status_code == 401
    assert c.post("/v1/auth/login", json={"email": "ADMIN@example.com ", "password": "correct horse battery"}).status_code == 200
    assert c.get("/v1/auth/me").json()["user"]["role"] == "admin"


def test_tampered_cookie_rejected(app_client):
    c = app_client
    _setup(c)
    raw = c.cookies.get("esign_session")
    c.cookies.set("esign_session", raw[:-1] + ("0" if raw[-1] != "0" else "1"))
    assert c.get("/v1/auth/me").json()["user"] is None


def test_users_are_isolated_and_admin_only(app_client):
    c = app_client
    _setup(c)
    r = c.post("/v1/auth/users", json={"email": "bob@example.com", "password": "bobs long password", "role": "member"})
    assert r.status_code == 200
    bob_id = r.json()["user"]["id"]
    # admin creates an envelope
    e1 = c.post("/v1/esign/envelopes", json={"title": "Admin deal"})
    assert e1.status_code == 200, e1.text
    # bob signs in on a separate client and sees nothing of the admin's
    b = TestClient(c.app, base_url="http://testserver")
    assert b.post("/v1/auth/login", json={"email": "bob@example.com", "password": "bobs long password"}).status_code == 200
    lst = b.get("/v1/esign/envelopes").json()
    items = lst.get("envelopes", lst.get("items", lst)) if isinstance(lst, dict) else lst
    assert not items
    eid = e1.json().get("id") or e1.json().get("envelope", {}).get("id")
    assert b.get(f"/v1/esign/envelopes/{eid}").status_code == 404
    assert b.get("/v1/auth/users").status_code == 403
    # disabling bob kills his session
    assert c.delete(f"/v1/auth/users/{bob_id}").status_code == 200
    assert b.get("/v1/auth/me").json()["user"] is None


def test_api_keys(app_client):
    c = app_client
    _setup(c)
    k = c.post("/v1/auth/keys", json={"label": "CI"}).json()
    assert k["key"].startswith("dsk_")
    api = TestClient(c.app, base_url="http://testserver")
    assert api.get("/v1/esign/envelopes", headers={"X-API-Key": k["key"]}).status_code == 200
    assert api.get("/v1/esign/envelopes", headers={"X-API-Key": "dsk_" + "0" * 40}).status_code == 401
    assert "key" not in c.get("/v1/auth/keys").json()["keys"][0]
    assert c.delete(f"/v1/auth/keys/{k['id']}").status_code == 200
    assert api.get("/v1/esign/envelopes", headers={"X-API-Key": k["key"]}).status_code == 401


def test_cross_site_write_refused(app_client):
    c = app_client
    _setup(c)
    r = c.post("/v1/esign/envelopes", json={"title": "x"}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    r = c.post("/v1/esign/envelopes", json={"title": "x"}, headers={"Origin": "http://testserver"})
    assert r.status_code == 200


def test_owner_routes_need_sign_in(app_client):
    assert app_client.get("/v1/esign/envelopes").status_code == 401


def test_sqlite_store_roundtrip(tmp_path):
    from esign.store import SqliteStore
    s = SqliteStore(str(tmp_path / "x.db"))
    did = s.store_document(b"abc", "application/pdf", "u:1", "esign", {"pipeline": "p", "k": 1}, owner="u:1")
    assert s.get_document(did, "u:1")["data"] == b"abc"
    assert s.get_document(did, "u:2") is None
    assert s.update_document_review(did, "u:1", {"k": 2})["k"] == 2
    assert s.list_documents("u:1", pipeline="p")[0]["review"]["k"] == 2
    assert s.list_pipeline_owners("p") == ["u:1"]
    assert s.delete_document(did, "u:2") is False and s.delete_document(did, "u:1") is True


def test_sender_defaults_to_the_signed_in_person(app_client):
    c = app_client
    _setup(c)                                       # admin "Ada", admin@example.com
    e = c.post("/v1/esign/envelopes", json={"title": "NDA"}).json()
    env = c.get(f"/v1/esign/envelopes/{e['id']}").json()
    assert env["sender_name"] == "Ada" and env["sender_email"] == "admin@example.com"
    e2 = c.post("/v1/esign/envelopes", json={"title": "NDA", "sender_name": "Legal team"}).json()
    assert c.get(f"/v1/esign/envelopes/{e2['id']}").json()["sender_name"] == "Legal team"
