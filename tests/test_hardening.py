"""Deployment hardening: the first-run setup token, sign-in limits that count by the real client address, 
request-body limits that apply before an upload is read, and shipped defaults that don't trust forwarded headers."""
import asyncio
import importlib
import sys
import re
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]

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


# ------------------------------------------------------------------------------------------- request-body limits
MB = 1024 * 1024
PDF = b"%PDF-1.4\n" + b"0" * 2048


@pytest.fixture()
def parsed(monkeypatch):
    """Counts how many multipart bodies the server started to parse (parsing is what spools an upload to disk)."""
    from starlette import formparsers
    calls = []
    real = formparsers.MultiPartParser.parse

    async def spy(self):
        calls.append(1)
        return await real(self)

    monkeypatch.setattr(formparsers.MultiPartParser, "parse", spy)
    return calls


def _signed_in(start, **env):
    c = start(**env)
    assert c.post("/v1/auth/setup", json={**ADMIN, "setup_token": TOKEN}).status_code == 200
    return c


def test_upload_from_a_stranger_is_refused_before_it_is_parsed(start, parsed):
    c = start()
    big = {"file": ("x.pdf", b"%PDF-1.4\n" + b"0" * (2 * MB), "application/pdf")}
    r = c.post("/v1/esign/verify", files=big)
    assert r.status_code == 401 and r.headers["x-content-type-options"] == "nosniff"
    assert c.post("/v1/esign/envelopes/" + "0" * 32 + "/documents", files=big).status_code == 401
    assert c.post("/v1/esign/verify", files=big, headers={"X-API-Key": "dsk_" + "0" * 40}).status_code == 401
    assert c.post("/v1/esign/envelopes", content=b"x" * 4096,
                  headers={"Content-Type": "application/json"}).status_code == 401
    assert parsed == []                               # nothing was read into a temp file


def test_oversized_upload_is_refused_by_its_declared_length(start, parsed):
    c = _signed_in(start)
    eid = c.post("/v1/esign/envelopes", json={"title": "Big"}).json()["id"]
    r = c.post(f"/v1/esign/envelopes/{eid}/documents",
               files={"file": ("big.pdf", b"%PDF-1.4\n" + b"0" * (27 * MB), "application/pdf")})
    assert r.status_code == 413 and "too large" in r.json()["detail"]
    assert parsed == []
    r = c.post(f"/v1/esign/envelopes/{eid}/documents", files={"file": ("small.pdf", PDF, "application/pdf")})
    assert r.status_code != 413 and parsed == [1]     # a normal upload still reaches the handler


def test_verify_keeps_its_own_limit_for_signed_in_users(start, parsed):
    c = _signed_in(start, ESIGN_VERIFY_MAX_MB="40")
    r = c.post("/v1/esign/verify", files={"file": ("a.bin", b"a" * (30 * MB), "application/octet-stream")})
    assert r.status_code == 200 and r.json()["match"] is False       # above the 25 MB document limit, still fine
    assert parsed == [1]
    r = c.post("/v1/esign/verify", files={"file": ("a.bin", b"a" * (42 * MB), "application/octet-stream")})
    assert r.status_code == 413 and parsed == [1]


def test_account_and_other_routes_have_small_limits(start):
    c = start()
    r = c.post("/v1/auth/login", json={"email": "a@example.com", "password": "x" * 100, "pad": "y" * (100 * 1024)})
    assert r.status_code == 413
    r = c.post("/v1/sign/" + "x" * 40 + "/complete", content=b"z" * (9 * MB),
               headers={"Content-Type": "application/json"})
    assert r.status_code == 413
    assert c.post("/v1/auth/login", json={"email": "a@example.com", "password": "wrong password"}).status_code == 401


def test_body_without_a_declared_length_is_cut_off_through_the_app(start):
    c = start()

    def chunks():
        for _ in range(4):
            yield b"y" * (50 * 1024)

    r = c.post("/v1/auth/login", content=chunks(), headers={"Content-Type": "application/json"})
    assert "content-length" not in r.request.headers
    assert r.status_code == 413


def _run_middleware(limit, chunks, headers=(), needs_auth=False, authenticate=None):
    """Drive BodyLimitMiddleware directly with a body that arrives in pieces; returns (status, bytes the app got)."""
    from esign import limits
    got, sent = [], []

    async def app(scope, receive, send):
        while True:
            m = await receive()
            got.append(len(m.get("body") or b""))
            if not m.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    pending = list(chunks)

    async def receive():
        body = pending.pop(0)
        return {"type": "http.request", "body": body, "more_body": bool(pending)}

    async def send(m):
        sent.append(m)

    mw = limits.BodyLimitMiddleware(app, rule=lambda method, path: (limit, needs_auth), authenticate=authenticate)
    scope = {"type": "http", "method": "POST", "path": "/x", "headers": list(headers), "query_string": b""}
    asyncio.run(mw(scope, receive, send))
    return sent[0]["status"], sum(got), len(pending)


def test_chunked_body_is_cut_off_at_the_limit():
    chunked = [(b"transfer-encoding", b"chunked")]
    status, got, unread = _run_middleware(3 * MB, [b"a" * MB] * 10, chunked)
    assert status == 413 and got <= 3 * MB and unread == 6           # stopped reading; the rest never left the socket
    assert _run_middleware(3 * MB, [b"a" * MB] * 3, chunked)[0] == 200
    assert _run_middleware(3 * MB, [b"a"], [(b"content-length", str(4 * MB).encode())])[:2] == (413, 0)
    assert _run_middleware(3 * MB, [b"a"], [(b"content-length", b"-5")])[:2] == (400, 0)
    assert _run_middleware(3 * MB, [b"a"], [(b"content-length", b"1, 1")])[:2] == (400, 0)


def test_sign_in_is_checked_before_the_body_is_read():
    chunked = [(b"transfer-encoding", b"chunked")]
    refuse = lambda request: (401, "Sign in first.")
    assert _run_middleware(MB, [b"a" * 10] * 3, chunked, True, refuse) == (401, 0, 3)
    assert _run_middleware(MB, [b"a" * 10] * 3, chunked, True, lambda request: None) == (200, 30, 0)
    assert _run_middleware(MB, [b""], [], True, refuse)[0] == 200    # no body: the route does its own check


# ------------------------------------------------------------------------------------------- shipped defaults
def test_shipped_defaults_do_not_trust_forwarded_headers():
    """The quick start (cp .env.example .env; docker compose up) must not let a signer pick the IP on the certificate:
    proxy trust is off unless the deployer turns it on, and the port is published on this machine only."""
    env = (ROOT / ".env.example").read_text()
    assert re.findall(r"^ESIGN_TRUST_PROXY=(.*)$", env, re.M) == ["0"]
    compose = (ROOT / "docker-compose.yml").read_text()
    ports = re.findall(r'^\s*-\s*"?([0-9.:]+:8000)"?\s*$', compose, re.M)
    assert ports and all(p.startswith("127.0.0.1:") for p in ports)
    render = (ROOT / "render.yaml").read_text()                         # Render's router is always in front
    assert re.search(r"key: ESIGN_TRUST_PROXY\s*\n\s*value: \"1\"", render)


def _req(xff=None, peer="192.0.2.10"):
    from starlette.requests import Request
    headers = [(b"x-forwarded-for", xff.encode())] if xff else []
    return Request({"type": "http", "headers": headers, "client": (peer, 1234)})


def test_forwarded_header_is_ignored_by_default(monkeypatch):
    from esign import esign as E
    assert E._ip(_req("198.51.100.99")) == "192.0.2.10"                 # ESIGN_TRUST_PROXY unset
    monkeypatch.setenv("ESIGN_TRUST_PROXY", "0")
    assert E._ip(_req("198.51.100.99")) == "192.0.2.10"
    monkeypatch.setenv("ESIGN_TRUST_PROXY", "true")                     # only the documented "1" turns it on
    assert E._ip(_req("198.51.100.99")) == "192.0.2.10"


def test_warns_once_when_the_proxy_setting_looks_wrong(monkeypatch, capsys):
    from esign import net
    monkeypatch.setattr(net, "_warned", set())
    net.client_ip(_req("198.51.100.99", peer="203.0.113.50"))           # public peer sending the header: no proxy
    assert capsys.readouterr().out == ""
    net.client_ip(_req("198.51.100.99", peer="172.18.0.1"))             # behind a proxy, trust is off
    net.client_ip(_req("198.51.100.98", peer="172.18.0.1"))
    out = capsys.readouterr().out
    assert out.count("WARNING") == 1 and "ESIGN_TRUST_PROXY=1" in out
    monkeypatch.setenv("ESIGN_TRUST_PROXY", "1")
    net.client_ip(_req("198.51.100.99, 203.0.113.7", peer="172.18.0.1"))   # as it should be: quiet
    assert capsys.readouterr().out == ""
    net.client_ip(_req(None, peer="203.0.113.50"))                      # trust is on, but this came in directly
    net.client_ip(_req(None, peer="203.0.113.51"))
    out = capsys.readouterr().out
    assert out.count("WARNING") == 1 and "ESIGN_TRUST_PROXY=0" in out
