"""Deployment hardening: the first-run setup token."""
import importlib
import sys
import threading

import pytest
from fastapi.testclient import TestClient

TOKEN = "setup-token-for-tests-0123456789"
ADMIN = {"email": "admin@example.com", "password": "correct horse battery", "name": "Ada"}


def _load_app(monkeypatch, tmp_path, **env):
    """Import esign.main afresh (as a server start would) with the given ESIGN_* settings."""
    monkeypatch.setenv("ESIGN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ESIGN_SECRET", "t" * 64)
    monkeypatch.setenv("ESIGN_TSA_URLS", "off")
    monkeypatch.delenv("ESIGN_DATABASE_URL", raising=False)
    for k, v in env.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)
    sys.modules.pop("esign.main", None)
    return importlib.import_module("esign.main")


@pytest.fixture()
def start(monkeypatch, tmp_path):
    def _start(**env):
        env.setdefault("ESIGN_SETUP_TOKEN", TOKEN)
        main = _load_app(monkeypatch, tmp_path, **env)
        return TestClient(main.app, base_url="http://testserver")
    return _start


# ------------------------------------------------------------------------------------------- first-run setup token
def test_setup_refused_without_the_token(start):
    c = start()
    assert c.get("/v1/auth/me").json() == {"user": None, "setup_needed": True}
    r = c.post("/v1/auth/setup", json=ADMIN)
    assert r.status_code == 403, r.text
    r = c.post("/v1/auth/setup", json={**ADMIN, "setup_token": "not-the-token-0123456789"})
    assert r.status_code == 403
    r = c.post("/v1/auth/setup", json={**ADMIN, "setup_token": TOKEN[:-1]})
    assert r.status_code == 403
    assert "esign_session" not in c.cookies
    assert c.get("/v1/auth/me").json()["setup_needed"] is True          # nobody became admin
    r = c.post("/v1/auth/setup", json={**ADMIN, "setup_token": TOKEN})
    assert r.status_code == 200 and r.json()["user"]["role"] == "admin"
    assert c.get("/v1/auth/me").json()["setup_needed"] is False


def test_setup_token_is_generated_and_logged_when_unset(start, tmp_path, capsys):
    c = start(ESIGN_SETUP_TOKEN=None)
    f = tmp_path / ".setup-token"
    token = f.read_text().strip()
    assert len(token) >= 32 and (f.stat().st_mode & 0o777) == 0o600
    assert ("Setup token: " + token) in capsys.readouterr().out
    assert c.post("/v1/auth/setup", json=ADMIN).status_code == 403
    assert c.post("/v1/auth/setup", json={**ADMIN, "setup_token": "0" * len(token)}).status_code == 403
    assert c.post("/v1/auth/setup", json={**ADMIN, "setup_token": token}).status_code == 200
    assert not f.exists()                                               # spent: removed once the admin exists


def test_generated_setup_token_survives_a_restart(start, tmp_path, capsys):
    start(ESIGN_SETUP_TOKEN=None)
    token = (tmp_path / ".setup-token").read_text().strip()
    c = start(ESIGN_SETUP_TOKEN=None)                                   # restart before anyone finished setup
    assert (tmp_path / ".setup-token").read_text().strip() == token
    assert c.post("/v1/auth/setup", json={**ADMIN, "setup_token": token}).status_code == 200


def test_setup_token_from_env_is_not_written_to_the_log(start, tmp_path, capsys):
    start()
    out = capsys.readouterr().out
    assert "ESIGN_SETUP_TOKEN" in out and TOKEN not in out
    assert not (tmp_path / ".setup-token").exists()


def test_no_setup_token_once_an_account_exists(start, tmp_path, capsys):
    c = start()
    assert c.post("/v1/auth/setup", json={**ADMIN, "setup_token": TOKEN}).status_code == 200
    capsys.readouterr()
    c2 = start(ESIGN_SETUP_TOKEN=None)                                  # restart of a server that is set up
    assert "Setup token" not in capsys.readouterr().out
    assert not (tmp_path / ".setup-token").exists()
    r = c2.post("/v1/auth/setup", json={"email": "x@example.com", "password": "another long pw", "setup_token": TOKEN})
    assert r.status_code == 409


def test_short_setup_token_refuses_to_start(monkeypatch, tmp_path):
    with pytest.raises(SystemExit) as e:
        _load_app(monkeypatch, tmp_path, ESIGN_SETUP_TOKEN="short")
    assert "ESIGN_SETUP_TOKEN" in str(e.value)


def test_first_admin_insert_is_atomic(tmp_path):
    from esign.store import SqliteStore
    s = SqliteStore(str(tmp_path / "x.db"))
    won, gate = [], threading.Barrier(8)

    def go(i):
        gate.wait()
        u = s.create_first_admin(f"a{i}@example.com", "", "hash")
        if u:
            won.append(u)

    threads = [threading.Thread(target=go, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(won) == 1 and won[0]["role"] == "admin" and s.count_users() == 1
    assert s.create_first_admin("late@example.com", "", "hash") is None


def test_cli_prints_the_pending_setup_token(start, tmp_path, capsys):
    from esign import cli
    start(ESIGN_SETUP_TOKEN=None)
    token = (tmp_path / ".setup-token").read_text().strip()
    capsys.readouterr()
    cli.main(["setup-token"])
    assert capsys.readouterr().out.strip() == token
