"""Accounts for the people who SEND envelopes (signers never need an account).

- First run: while no user exists, POST /v1/auth/setup creates the first admin. It needs the setup token: the value
  of ESIGN_SETUP_TOKEN, or (if that is unset) a random one written to the server log and to <data dir>/.setup-token.
  Without it, whoever reached a fresh deployment first could make themselves the admin.
- Browser sessions: a signed, HttpOnly cookie (HMAC-SHA256 over user id + session version + expiry with ESIGN_SECRET).
  Signing out everywhere / disabling a user bumps session_ver, which kills every cookie that user holds.
- API keys: "dsk_" + 40 hex chars, sent as X-API-Key; only a SHA-256 of the key is stored.
- Every user is their own envelope owner ("u:<user id>"): people see only their own envelopes.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field

router = APIRouter()
COOKIE = "esign_session"
SESSION_DAYS = int(os.environ.get("ESIGN_SESSION_DAYS") or 14)
_EMAIL = re.compile(r"^[^@\s<>\"']+@[^@\s<>\"']+\.[^@\s<>\"']{2,}$")
_store = None
_secret: bytes = b""


def configure(store, secret: bytes):
    global _store, _secret
    _store, _secret = store, secret


# ------------------------------------------------------------------------------------------------ first-run token
SETUP_TOKEN_FILE = ".setup-token"
SETUP_TOKEN_MIN = 16
_setup_token: str = ""                               # empty = first-run setup over HTTP is refused
_setup_token_file: Optional[Path] = None
_setup_lock = threading.Lock()


def pending_setup_token(data_dir) -> tuple:
    """(token, source) while no user exists, else ("", ""). source is "env" (ESIGN_SETUP_TOKEN) or "file" (a random
    token kept in <data dir>/.setup-token, created here if missing)."""
    if _store.count_users() > 0:
        return "", ""
    env = (os.environ.get("ESIGN_SETUP_TOKEN") or "").strip()
    if env:
        if len(env) < SETUP_TOKEN_MIN:
            sys.exit(f"ESIGN_SETUP_TOKEN must be at least {SETUP_TOKEN_MIN} characters (try: openssl rand -hex 16)")
        return env, "env"
    f = Path(data_dir) / SETUP_TOKEN_FILE
    try:
        tok = f.read_text().strip()
    except OSError:
        tok = ""
    if len(tok) < SETUP_TOKEN_MIN:
        tok = secrets.token_hex(16)
        fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(tok + "\n")
        f.chmod(0o600)
    return tok, "file"


def init_setup_token(data_dir) -> None:
    """Called once at start-up. On a fresh deployment this decides the token POST /v1/auth/setup must carry and tells
    the operator (and nobody else) where to find it: the server log."""
    global _setup_token, _setup_token_file
    _setup_token_file = Path(data_dir) / SETUP_TOKEN_FILE
    _setup_token, source = pending_setup_token(data_dir)
    if not _setup_token:
        _forget_setup_token()
        return
    line = "=" * 78
    print(line)
    print("First run: no admin account exists yet. The first-run page asks for a setup token.")
    if source == "env":
        print("Setup token: the value of ESIGN_SETUP_TOKEN in this server's environment.")
    else:
        print("Setup token: " + _setup_token)
        print(f"(also saved in {_setup_token_file}; set ESIGN_SETUP_TOKEN to choose your own)")
    print(line, flush=True)


def _forget_setup_token() -> None:
    global _setup_token
    _setup_token = ""
    try:
        if _setup_token_file is not None:
            _setup_token_file.unlink()
    except OSError:
        pass


def _setup_token_ok(supplied: str) -> bool:
    supplied = (supplied or "").strip()
    if not _setup_token or not supplied:
        return False
    return hmac.compare_digest(supplied.encode(), _setup_token.encode())


# ------------------------------------------------------------------------------------------------ passwords
def hash_pw(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def check_pw(pw: str, stored: str) -> bool:
    try:
        _, s, d = stored.split("$")
        dk = hashlib.scrypt(pw.encode(), salt=base64.b64decode(s), n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(dk, base64.b64decode(d))
    except Exception:
        return False


_DUMMY = hash_pw(secrets.token_hex(8))               # equal-time check for unknown emails


# ------------------------------------------------------------------------------------------------ sessions
def _sign(msg: str) -> str:
    return hmac.new(_secret, msg.encode(), hashlib.sha256).hexdigest()[:40]


def _make_cookie(user: dict) -> str:
    exp = int(time.time()) + SESSION_DAYS * 86400
    msg = f"{user['id']}.{user['session_ver']}.{exp}"
    return msg + "." + _sign(msg)


def _user_from_cookie(request: Request) -> Optional[dict]:
    raw = request.cookies.get(COOKIE) or ""
    parts = raw.split(".")
    if len(parts) != 4:
        return None
    uid, ver, exp, mac = parts
    if not hmac.compare_digest(mac, _sign(f"{uid}.{ver}.{exp}")):
        return None
    if not exp.isdigit() or int(exp) < time.time():
        return None
    u = _store.get_user(uid)
    if not u or u["disabled"] or str(u["session_ver"]) != ver:
        return None
    return u


def _user_from_key(key: str) -> Optional[dict]:
    if not key or not key.startswith("dsk_"):
        return None
    u = _store.user_for_key(hashlib.sha256(key.encode()).hexdigest())
    return u if u and not u["disabled"] else None


def _check_origin(request: Request):
    """Cookie-authenticated writes must come from our own pages (CSRF): same-origin Origin/Referer, or none."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    origin = request.headers.get("origin") or ""
    if not origin:
        return                                       # non-browser client; SameSite=Lax still blocks cross-site forms
    host = request.headers.get("host") or ""
    public = (os.environ.get("ESIGN_PUBLIC_URL") or "").rstrip("/")
    if origin.split("://", 1)[-1] != host and origin != public:
        raise HTTPException(status_code=403, detail="Cross-site request refused.")


def current_user(request: Request, x_api_key: Optional[str] = None) -> Optional[dict]:
    if x_api_key:
        return _user_from_key(x_api_key)
    u = _user_from_cookie(request)
    if u:
        _check_origin(request)
    return u


def owner_id(user: dict) -> str:
    return "u:" + user["id"]


def require_key(request: Request, x_api_key: Optional[str] = None) -> str:
    """What esign.py calls for every owner route: returns the owner id or raises 401."""
    u = current_user(request, x_api_key)
    if not u:
        raise HTTPException(status_code=401, detail="Sign in first.")
    return owner_id(u)


def session_label(request: Request) -> Optional[str]:
    u = _user_from_cookie(request)
    return owner_id(u) if u else None


def _require_user(request: Request, x_api_key: Optional[str]) -> dict:
    u = current_user(request, x_api_key)
    if not u:
        raise HTTPException(status_code=401, detail="Sign in first.")
    return u


def _require_admin(request: Request, x_api_key: Optional[str]) -> dict:
    u = _require_user(request, x_api_key)
    if u["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only an admin can do that.")
    return u


def _public(u: dict) -> dict:
    return {"id": u["id"], "email": u["email"], "name": u["name"], "role": u["role"],
            "disabled": bool(u["disabled"]), "created_at": u["created_at"]}


def _set_cookie(resp: Response, request: Request, user: dict):
    secure = request.url.scheme == "https" or (os.environ.get("ESIGN_PUBLIC_URL") or "").startswith("https://")
    resp.set_cookie(COOKIE, _make_cookie(user), max_age=SESSION_DAYS * 86400, httponly=True, secure=secure,
                    samesite="lax", path="/")


# ------------------------------------------------------------------------------------------------ rate limit
_hits: dict = {}


def _throttle(key: str, limit: int, window: int = 900):
    now = time.time()
    q = [t for t in _hits.get(key, []) if now - t < window]
    if len(q) >= limit:
        raise HTTPException(status_code=429, detail="Too many attempts — try again in a few minutes.")
    q.append(now)
    _hits[key] = q


def _ip(request: Request) -> str:
    if os.environ.get("ESIGN_TRUST_PROXY") == "1":
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "?"


# ------------------------------------------------------------------------------------------------ routes
class Creds(BaseModel):
    email: str = Field(..., max_length=200)
    password: str = Field(..., max_length=200)


class SetupIn(Creds):
    name: str = Field("", max_length=120)
    setup_token: str = Field("", max_length=200)


class UserIn(BaseModel):
    email: str = Field(..., max_length=200)
    name: str = Field("", max_length=120)
    role: str = Field("member", pattern="^(admin|member)$")
    password: str = Field(..., min_length=10, max_length=200)


class PwIn(BaseModel):
    current: str = Field(..., max_length=200)
    new: str = Field(..., min_length=10, max_length=200)


class KeyIn(BaseModel):
    label: str = Field("", max_length=80)


def _norm_email(e: str) -> str:
    e = (e or "").strip().lower()
    if not _EMAIL.match(e):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")
    return e


@router.get("/v1/auth/me")
def me(request: Request, x_api_key: Optional[str] = Header(default=None)):
    u = current_user(request, x_api_key)
    return {"user": _public(u) if u else None, "setup_needed": _store.count_users() == 0}


@router.post("/v1/auth/setup")
def setup(body: SetupIn, request: Request, response: Response):
    _throttle("setup:" + _ip(request), 10)
    if _store.count_users() > 0:
        raise HTTPException(status_code=409, detail="Setup is already done — sign in instead.")
    if not _setup_token_ok(body.setup_token):
        raise HTTPException(status_code=403, detail="That setup token isn't right. It is the ESIGN_SETUP_TOKEN "
                                                    "setting of this server, or the token in its start-up log.")
    if len(body.password) < 10:
        raise HTTPException(status_code=422, detail="Use a password of at least 10 characters.")
    email, pw_hash = _norm_email(body.email), hash_pw(body.password)
    with _setup_lock:                                # the "is it still empty?" check and the insert are one step
        u = _store.create_first_admin(email, body.name.strip(), pw_hash)
        if u:
            _forget_setup_token()
    if not u:
        raise HTTPException(status_code=409, detail="Setup is already done — sign in instead.")
    _set_cookie(response, request, u)
    return {"user": _public(u)}


@router.post("/v1/auth/login")
def login(body: Creds, request: Request, response: Response):
    _throttle("login:" + _ip(request), 20)
    email = (body.email or "").strip().lower()
    _throttle("login-user:" + email, 10)
    u = _store.get_user_by_email(email)
    ok = check_pw(body.password, u["pw_hash"] if u else _DUMMY)
    if not u or not ok or u["disabled"]:
        raise HTTPException(status_code=401, detail="Wrong email or password.")
    _set_cookie(response, request, u)
    return {"user": _public(u)}


@router.post("/v1/auth/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@router.post("/v1/auth/logout-everywhere")
def logout_everywhere(request: Request, response: Response, x_api_key: Optional[str] = Header(default=None)):
    u = _require_user(request, x_api_key)
    _store.update_user(u["id"], session_ver=int(u["session_ver"]) + 1)
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@router.post("/v1/auth/password")
def change_password(body: PwIn, request: Request, response: Response,
                    x_api_key: Optional[str] = Header(default=None)):
    u = _require_user(request, x_api_key)
    if not check_pw(body.current, u["pw_hash"]):
        raise HTTPException(status_code=401, detail="Your current password is wrong.")
    u = _store.update_user(u["id"], pw_hash=hash_pw(body.new), session_ver=int(u["session_ver"]) + 1)
    _set_cookie(response, request, u)
    return {"ok": True}


@router.get("/v1/auth/users")
def list_users(request: Request, x_api_key: Optional[str] = Header(default=None)):
    _require_admin(request, x_api_key)
    return {"users": [_public(u) for u in _store.list_users()]}


@router.post("/v1/auth/users")
def add_user(body: UserIn, request: Request, x_api_key: Optional[str] = Header(default=None)):
    _require_admin(request, x_api_key)
    email = _norm_email(body.email)
    if _store.get_user_by_email(email):
        raise HTTPException(status_code=409, detail="That email already has an account.")
    u = _store.create_user(email, body.name.strip(), body.role, hash_pw(body.password))
    return {"user": _public(u)}


@router.delete("/v1/auth/users/{uid}")
def disable_user(uid: str, request: Request, x_api_key: Optional[str] = Header(default=None)):
    admin = _require_admin(request, x_api_key)
    if uid == admin["id"]:
        raise HTTPException(status_code=409, detail="You can't disable your own account.")
    u = _store.get_user(uid)
    if not u:
        raise HTTPException(status_code=404, detail="No such user.")
    # Disabled, not deleted: their envelopes and audit trails are records and stay.
    _store.update_user(uid, disabled=1, session_ver=int(u["session_ver"]) + 1)
    return {"ok": True}


@router.get("/v1/auth/keys")
def list_keys(request: Request, x_api_key: Optional[str] = Header(default=None)):
    u = _require_user(request, x_api_key)
    return {"keys": _store.list_keys(u["id"])}


@router.post("/v1/auth/keys")
def create_key(body: KeyIn, request: Request, x_api_key: Optional[str] = Header(default=None)):
    u = _require_user(request, x_api_key)
    key = "dsk_" + secrets.token_hex(20)
    rec = _store.create_key(u["id"], body.label.strip() or "API key",
                            hashlib.sha256(key.encode()).hexdigest(), key[:10])
    return {**rec, "key": key}                       # shown once; only the hash is stored


@router.delete("/v1/auth/keys/{kid}")
def revoke_key(kid: str, request: Request, x_api_key: Optional[str] = Header(default=None)):
    u = _require_user(request, x_api_key)
    if not _store.revoke_key(u["id"], kid):
        raise HTTPException(status_code=404, detail="No such key.")
    return {"ok": True}
