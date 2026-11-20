"""Deployment hardening: the first-run setup token, and sign-in limits that count by the real client address."""
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


# ------------------------------------------------------------------------------------------- sign-in limits
PROXY = "203.0.113.7"                                # the hop our own proxy appends: the real client address


def _login(c, email, pw, addr=None, spoof=None):
    """A sign-in as it arrives through the proxy: X-Forwarded-For = [what the client sent, ] real address."""
    headers = {}
    if addr:
        headers["X-Forwarded-For"] = (spoof + ", " if spoof else "") + addr
    return c.post("/v1/auth/login", json={"email": email, "password": pw}, headers=headers)


def _admin(c):
    r = c.post("/v1/auth/setup", json={**ADMIN, "setup_token": TOKEN})
    assert r.status_code == 200, r.text
    c.cookies.clear()


def test_one_rule_for_the_client_address(monkeypatch):
    from starlette.requests import Request
    from esign import auth, esign as E, net

    def req(xff=None, peer="192.0.2.10"):
        headers = [(b"x-forwarded-for", xff.encode())] if xff else []
        return Request({"type": "http", "headers": headers, "client": (peer, 1234)})

    monkeypatch.setenv("ESIGN_TRUST_PROXY", "1")
    r = req("198.51.100.99, 203.0.113.7")
    assert net.client_ip(r) == E._client_ip(r) == auth._ip(r) == "203.0.113.7"       # last hop, never the first
    assert auth._ip(req("2001:db8:1:2:aaaa::1")) == E._ipk(req("2001:db8:1:2:bbbb::2")) == "2001:db8:1:2::/64"
    assert auth._ip(req("not an address")) == "192.0.2.10"
    monkeypatch.setenv("ESIGN_TRUST_PROXY", "0")
    assert net.client_ip(r) == E._client_ip(r) == auth._ip(r) == "192.0.2.10"        # header ignored entirely


def test_sign_in_limit_ignores_hops_the_client_sent(start):
    c = start(ESIGN_TRUST_PROXY="1")
    codes = [_login(c, f"user{i}@example.com", "wrong password", PROXY, spoof=f"198.51.100.{i}").status_code
             for i in range(24)]
    assert codes[:20] == [401] * 20 and codes[20:] == [429] * 4


def test_setup_limit_ignores_hops_the_client_sent(start):
    c = start(ESIGN_TRUST_PROXY="1")
    codes = [c.post("/v1/auth/setup", json=ADMIN, headers={"X-Forwarded-For": f"198.51.100.{i}, {PROXY}"}).status_code
             for i in range(12)]
    assert codes[:10] == [403] * 10 and codes[10:] == [429] * 2


def test_forwarded_header_means_nothing_without_trust_proxy(start):
    c = start()
    codes = [c.post("/v1/auth/login", json={"email": f"user{i}@example.com", "password": "wrong password"},
                    headers={"X-Forwarded-For": f"198.51.100.{i}"}).status_code for i in range(22)]
    assert codes[:20] == [401] * 20 and codes[20:] == [429] * 2


def test_wrong_passwords_from_one_address_do_not_lock_the_account(start):
    c = start(ESIGN_TRUST_PROXY="1")
    _admin(c)
    attacker, owner = "198.51.100.66", "192.0.2.44"
    codes = [_login(c, ADMIN["email"], "wrong password", attacker).status_code for _ in range(13)]
    assert codes[:10] == [401] * 10 and codes[10:] == [429] * 3
    assert _login(c, ADMIN["email"], ADMIN["password"], attacker).status_code == 429   # that address stays shut out
    assert _login(c, ADMIN["email"], ADMIN["password"], owner).status_code == 200      # the real owner is not


def test_a_successful_sign_in_clears_the_wrong_password_count(start):
    c = start(ESIGN_TRUST_PROXY="1")
    _admin(c)
    addr = "192.0.2.44"
    assert [_login(c, ADMIN["email"], "wrong password", addr).status_code for _ in range(8)] == [401] * 8
    assert _login(c, ADMIN["email"], ADMIN["password"], addr).status_code == 200
    c.cookies.clear()
    assert [_login(c, ADMIN["email"], "wrong password", addr).status_code for _ in range(8)] == [401] * 8


def test_guessing_from_many_addresses_slows_strangers_but_not_the_owner(start, monkeypatch):
    import time
    from esign import auth
    monkeypatch.setattr(auth, "check_pw", lambda pw, stored: pw == ADMIN["password"])   # skip the slow hash
    monkeypatch.setattr(auth, "LOGIN_SLOW_GAP", 0.3)
    c = start(ESIGN_TRUST_PROXY="1")
    _admin(c)
    owner = "192.0.2.44"
    assert _login(c, ADMIN["email"], ADMIN["password"], owner).status_code == 200      # the owner's usual address
    c.cookies.clear()
    for a in range(5):                                                                 # 50 wrong passwords, 5 addresses
        for _ in range(10):
            assert _login(c, ADMIN["email"], "wrong password", f"198.51.100.{a}").status_code == 401
    assert _login(c, ADMIN["email"], "wrong password", "198.51.100.200").status_code == 401   # takes the one slot
    r = _login(c, ADMIN["email"], "wrong password", "198.51.100.201")
    assert r.status_code == 429 and r.headers.get("retry-after")
    assert _login(c, ADMIN["email"], ADMIN["password"], owner).status_code == 200      # known address: not slowed
    c.cookies.clear()
    time.sleep(0.35)
    assert _login(c, ADMIN["email"], ADMIN["password"], "192.0.2.99").status_code == 200   # slowed, never locked


def test_limit_counters_are_bounded():
    from esign import net
    w = net.Window(max_keys=50, max_hits=20)
    for i in range(500):
        w.add(f"k{i}", 900)
    assert len(w) == 50 and w.count("k499", 900) == 1 and w.count("k0", 900) == 0
    for _ in range(200):
        w.add("busy", 900)
    assert w.count("busy", 900) == 20
    assert w.hit("x", 2, 900) and w.hit("x", 2, 900) and not w.hit("x", 2, 900)
    w.clear("x")
    assert w.hit("x", 2, 900)
