"""E-Sign — a self-hosted, DocuSign-style e-signature service.

The owner prepares an ENVELOPE (documents + recipients + fields) and sends it; the server generates a unique signing
LINK per recipient. Links are either emailed by the server (when outgoing mail is configured and switched on with
ESIGN_MAIL=1, and the owner ticks "email the links") or copied by the owner and shared however they like. Everything is
tracked — link generated → shared / emailed → viewed → signed / declined — in an append-only, SHA-256 hash-chained
audit trail; on completion the documents are flattened with every signature and a Certificate of Completion is
appended.

Storage: an owner-scoped document store (store.py — SQLite or Postgres): one JSON record per envelope (pipeline
"esign_envelope") + one blob row per file (pipeline "esign_blob": original upload — PDF, image or Word/ODT/RTF exactly
as uploaded —, normalized PDF (Word files converted by headless LibreOffice, see esign_pdf.office_to_pdf), working
copy, signature PNGs, final PDF). Files are encrypted at rest when ESIGN_ENC_KEY (a Fernet key) is set. The store's
update is a read-modify-write, so every envelope mutation runs under a per-envelope lock (run a single worker
process; sync routes run in its threadpool).

Links: "{eid}.{rid}.{v}.{mac}" with mac = HMAC-SHA256(key, "esign|eid|rid|v")[:32], key derived from ESIGN_SECRET —
nothing secret is stored; "regenerate" bumps the per-recipient version v so the old link dies at once. Optional
per-recipient access code (salted hash, 5 tries then a 15-minute lock) and email one-time code.

Legal posture: a simple electronic signature (intent + ESIGN consent + per-signer link + audit trail + hashes). Not a
qualified signature. Every completed envelope's PDF is SEALED (esign_seal.py): a PAdES digital seal by this server's
document-seal certificate plus an RFC 3161 timestamp from an independent TSA, so any PDF reader can show the file is
unchanged since completion and when it was sealed. The seal strengthens the evidence; on its own it does not make a
signer's signature advanced or qualified.
"""
from __future__ import annotations

import copy
import datetime as _dt
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import threading
import time
from collections import OrderedDict, deque
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, File, Header, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from . import esign_pdf as P
from . import esign_seal as SEAL
from . import brand
from . import net

router = APIRouter()
STATIC = Path(__file__).resolve().parent / "static"

PIPE_ENV = "esign_envelope"
PIPE_BLOB = "esign_blob"
ROLES = ("signer", "cc", "viewer")
ACTORS = ("signer", "viewer")                       # roles that must act (cc never blocks routing)
FIELD_TYPES = ("signature", "initials", "date_signed", "name", "email", "company", "title", "text", "checkbox", "date")
TEXTLIKE = ("name", "email", "company", "title", "text", "date")
MAX_DOCS, MAX_PAGES, MAX_RECIPIENTS, MAX_FIELDS = 20, 200, 30, 600
MAX_ENVELOPE_BYTES = 60 * 1024 * 1024
MAX_EVENTS = 3000                                   # cap applies ONLY to noisy, externally-triggerable events
_NOISY_EVENTS = {"viewed", "access_code_ok", "access_code_failed", "downloaded", "email_code_sent", "email_code_ok",
                 "email_code_failed"}
AC_HARD_LOCK = 20                                   # cumulative wrong codes before the link is locked for good
VIEW_EVENT_GAP = 600                                # seconds between logged "viewed" events per recipient
AC_MAX_FAILS, AC_LOCK_SECS = 5, 15 * 60
EC_TTL, EC_RESEND_GAP, EC_MAX_SENDS_HOUR = 10 * 60, 60, 5    # email one-time codes: lifetime, resend gap, sends/hour
EC_HARD_LOCK = 20                                   # cumulative wrong email codes before the link is locked for good
EC_OWNER_DAY, EC_GLOBAL_DAY = 300, 3000             # email-code sends per owner / per server per day
MAIL_OWNER_DAY = int(os.environ.get("ESIGN_MAIL_DAILY_CAP") or 300)   # envelope emails per account a day
MAIL_GLOBAL_DAY = max(2000, MAIL_OWNER_DAY)          # ... and per server a day
MAIL_TO_DAY, MAIL_ADDR_DAY = 20, 100                # ... per (account, address), and per address across accounts
MAIL_NOTE_DAY = 100                                 # notes to one sender address per account a day
MAIL_FAILNOTE_DAY = 3                               # "we couldn't email" notes per envelope a day
MAIL_RESCAN = 30 * 60                               # the delivery loop re-reads every envelope's outbox this often
MAIL_TRIES, MAIL_BACKOFF = 4, (60, 300, 900)        # delivery attempts, and the waits between them
MAIL_CHUNK, MAIL_STALE = 5, 600                     # jobs claimed per round; a claim older than this looks lost
MAIL_ATTACH_MAX = 10 * 1024 * 1024                  # completed copies are attached up to this size (else a link)
MAIL_WAIT = 8.0                                     # seconds an owner request waits for its emails before answering
MAIL_OUTBOX_MAX = 200
REMIND_GAP, REMIND_DAY = 10 * 60, 5                 # owner reminders: minimum gap, and per recipient per day
RELINK_DAY = 5                                      # new links emailed by regenerate / correct, per recipient per day
MAIL_SYNC = False                                   # tests: deliver emails in the request's own thread
_EMAIL = re.compile(r"^[^@\s<>\"']+@[^@\s<>\"']+\.[^@\s<>\"']{2,}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_RID = re.compile(r"^rcp_[0-9a-f]{10}$")
_VER = re.compile(r"^[0-9]{1,6}$")
_MAC = re.compile(r"^[0-9a-f]{32}$")
_FID = re.compile(r"^fld_[0-9a-f]{10}$")
_DID = re.compile(r"^doc_[0-9a-f]{10}$")
_PUB_HEADERS = {"X-Frame-Options": "DENY", "Content-Security-Policy": "frame-ancestors 'none'",
                "Referrer-Policy": "no-referrer", "Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow",
                "X-Content-Type-Options": "nosniff"}

# ------------------------------------------------------------------------------------------------- wiring
_get_repo = None
_require_key = None
_session_label = None
_session_payload = None
_log_activity = None


_owner_profile = None


def configure(get_repo, require_key=None, session_label=None, log_activity=None, session_payload=None,
              owner_profile=None):
    """main.py wires the document store + its auth helpers (avoids a circular import).
    get_repo() -> the store; require_key(request, x_api_key) -> owner id or raises 401; session_label(request) ->
    owner id for a logged-in browser session or None (page images skip the API rate limit); log_activity(request,
    event_type, caller, payload, response) is optional."""
    global _get_repo, _require_key, _session_label, _log_activity, _session_payload
    _get_repo, _require_key, _session_label, _log_activity = get_repo, require_key, session_label, log_activity
    _session_payload = session_payload
    global _owner_profile
    _owner_profile = owner_profile          # owner id -> {"name", "email"} of the account (sender defaults)


def _profile(owner) -> dict:
    if _owner_profile is None:
        return {}
    try:
        return _owner_profile(owner) or {}
    except Exception:
        return {}


def _repo():
    if _get_repo is None:
        raise HTTPException(status_code=503, detail="E-Sign not initialised")
    return _get_repo()


def _caller(request: Request, x_api_key: Optional[str] = Header(default=None)) -> str:
    """Owner auth = the app's require_key (API key or browser session)."""
    if _require_key is None:
        raise HTTPException(status_code=503, detail="E-Sign not initialised")
    return _require_key(request, x_api_key)


def _writer(request: Request, x_api_key: Optional[str] = Header(default=None)) -> str:
    """Owner auth for anything that CHANGES an envelope (the same check as reading; kept separate so a host app can
    add read-only roles)."""
    return _caller(request, x_api_key)


def _img_caller(request: Request, x_api_key: Optional[str] = Header(default=None)) -> str:
    """Page images: a logged-in session is accepted WITHOUT consuming the per-minute session rate limit (an editor
    loads many page images); otherwise fall back to the full require_key check (API keys)."""
    if _session_label is not None:
        lab = _session_label(request)
        if lab:
            return lab
    return _caller(request, x_api_key)


def _owner_log(request, event_type, caller, payload=None, response=None):
    if _log_activity is None:
        return
    try:
        _log_activity(request, event_type, caller, payload, response)
    except Exception:
        pass


# ------------------------------------------------------------------------------------------------- helpers
def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_dt() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _parse_iso(s) -> Optional[_dt.datetime]:
    if not s or not isinstance(s, str):
        return None
    try:
        t = s.strip().replace("Z", "+00:00")
        d = _dt.datetime.fromisoformat(t)
        if d.tzinfo is None:
            d = d.replace(tzinfo=_dt.timezone.utc)
        return d.astimezone(_dt.timezone.utc)
    except Exception:
        return None


def _iso(d: _dt.datetime) -> str:
    return d.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hex(n: int) -> str:
    return secrets.token_hex(n)[: 2 * n]


def _clean(s, maxlen: int) -> str:
    s = "" if s is None else str(s)
    s = "".join(ch for ch in s if ch == "\n" or ch == "\t" or (ord(ch) >= 32 and ord(ch) != 127))
    return s.strip()[:maxlen]


def _client_ip(request: Optional[Request]) -> str:
    """The visitor's IP: the last X-Forwarded-For hop when ESIGN_TRUST_PROXY=1, else the TCP peer (see net.py; the
    sign-in limits use the same rule)."""
    return net.client_ip(request)


def _limit_key(ip: str) -> str:
    """What per-IP rate limits count by: the IPv4 address, or the IPv6 /64."""
    return net.limit_key(ip)


def _ip(request: Optional[Request]) -> str:
    """The signer's IP (evidence on the certificate)."""
    return _client_ip(request)[:64]


def _ipk(request: Optional[Request]) -> str:
    """What the per-IP rate limits count by."""
    return _limit_key(_client_ip(request))[:64]


async def _read_body(request: Request, cap: int) -> Optional[bytes]:
    """Read a request body without ever buffering more than `cap` bytes (None = too large)."""
    try:
        if int(request.headers.get("content-length") or 0) > cap:
            return None
    except ValueError:
        return None
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > cap:
            return None
    return bytes(buf)


def _meta(request: Optional[Request]) -> dict:
    if request is None:
        return {"ip": "", "ua": "", "cookies": {}}
    return {"ip": _ip(request), "ua": (request.headers.get("user-agent") or "")[:300],
            "cookies": dict(request.cookies or {}),
            "https": (request.url.scheme == "https"
                      or (request.headers.get("x-forwarded-proto") or "").lower().startswith("https"))}


# ---- in-process sliding-window rate limiter (bounded) ----
_RL: "OrderedDict[str, deque]" = OrderedDict()
_RL_LOCK = threading.Lock()


def _rate_ok(key: str, limit: int, window: int = 60) -> bool:
    now = time.time()
    with _RL_LOCK:
        q = _RL.get(key)
        if q is None:
            q = _RL[key] = deque()
            if len(_RL) > 20000:                 # bound memory: drop the oldest keys
                for _ in range(2000):
                    _RL.popitem(last=False)
        else:
            _RL.move_to_end(key)
        while q and q[0] < now - window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True


def _rate(request: Request, bucket: str, limit: int):
    if not _rate_ok(f"{bucket}:{_ipk(request)}", limit):
        raise HTTPException(status_code=429, detail="Too many requests — please wait a moment and try again.",
                            headers=_PUB_HEADERS)


def _perr(status: int, detail: str, extra: Optional[dict] = None):
    return JSONResponse({"detail": detail, **(extra or {})}, status_code=status, headers=_PUB_HEADERS)


# ---- per-envelope locks ----
_LOCKS: dict = {}
_LOCKS_GUARD = threading.Lock()


def _lock(eid: str) -> threading.RLock:
    with _LOCKS_GUARD:
        lk = _LOCKS.get(eid)
        if lk is None:
            lk = _LOCKS[eid] = threading.RLock()
        return lk


# ---- store ----
class EncKeyError(RuntimeError):
    pass


def _enc_key():
    """The Fernet key files are encrypted with, or None when ESIGN_ENC_KEY is not set. A key that is set but not
    usable is an error, never a silent fall-back to storing files unencrypted."""
    k = (os.environ.get("ESIGN_ENC_KEY") or "").strip()
    if not k:
        return None
    try:
        from cryptography.fernet import Fernet
        return Fernet(k.encode())
    except Exception as e:
        raise EncKeyError("ESIGN_ENC_KEY is set but is not a valid Fernet key (32 url-safe base64-encoded bytes). "
                          "Generate one with: python -c \"from cryptography.fernet import Fernet; "
                          "print(Fernet.generate_key().decode())\"") from e


def check_enc_key() -> None:
    """Call at start-up: raises EncKeyError when ESIGN_ENC_KEY is set but unusable."""
    _enc_key()


def _load(eid: str, owner: Optional[str] = None) -> Optional[dict]:
    """A private COPY of the envelope (Memory returns live dicts; Postgres needs the real owner on update)."""
    if not eid or not _HEX32.match(eid):
        return None
    rec = _repo().get_document_review(eid, owner)
    if not isinstance(rec, dict) or rec.get("pipeline") != PIPE_ENV:
        return None
    if owner is not None and rec.get("owner") != owner:
        return None
    return copy.deepcopy(rec)


def _save(env: dict) -> None:
    env["updated_at"] = _now()
    if _repo().update_document_review(env["id"], env["owner"], copy.deepcopy(env)) is None:
        raise HTTPException(status_code=500, detail="Could not save the envelope — please try again.")


def _put_blob(owner: str, eid: str, kind: str, data: bytes, ctype: str) -> str:
    stored, ct = data, ctype
    f = _enc_key()
    if f is not None:
        stored, ct = f.encrypt(data), ctype + "+fernet"
    rec = {"pipeline": PIPE_BLOB, "envelope_id": eid, "kind": kind, "owner": owner, "size": len(data),
           "sha256": P.sha256(data), "created_at": _now()}
    bid = _repo().store_document(stored, ct, owner, "esign", rec, owner=owner)
    if not bid:
        raise HTTPException(status_code=500, detail="Could not store the file — please try again.")
    return bid


_BLOB_CACHE: "OrderedDict[str, bytes]" = OrderedDict()
_BLOB_CACHE_BYTES = [0]
_BLOB_CACHE_MAX = 96 * 1024 * 1024
_CACHE_LOCK = threading.Lock()


def _get_blob(owner: str, bid: str) -> bytes:
    """Blobs are immutable (a new working copy is a new blob), so they are safe to cache by id."""
    if not bid:
        raise HTTPException(status_code=404, detail="file not found")
    with _CACHE_LOCK:
        hit = _BLOB_CACHE.get(f"{owner}|{bid}")
        if hit is not None:
            _BLOB_CACHE.move_to_end(f"{owner}|{bid}")
            return hit
    d = _repo().get_document(bid, owner)
    if not d or d.get("data") is None:
        raise HTTPException(status_code=404, detail="file not found")
    data, ct = bytes(d["data"]), (d.get("content_type") or "")
    if ct.endswith("+fernet"):
        f = _enc_key()
        if f is None:
            raise HTTPException(status_code=503, detail="This file is encrypted and the decryption key is not configured.")
        data = f.decrypt(data)
    with _CACHE_LOCK:
        k = f"{owner}|{bid}"
        _BLOB_CACHE[k] = data
        _BLOB_CACHE_BYTES[0] += len(data)
        while _BLOB_CACHE_BYTES[0] > _BLOB_CACHE_MAX and _BLOB_CACHE:
            _, old = _BLOB_CACHE.popitem(last=False)
            _BLOB_CACHE_BYTES[0] -= len(old)
    return data


def _del_blob(owner: str, bid: Optional[str]) -> None:
    if not bid:
        return
    try:
        _repo().delete_document(bid, owner)
    except Exception:
        pass
    with _CACHE_LOCK:
        old = _BLOB_CACHE.pop(f"{owner}|{bid}", None)
        if old is not None:
            _BLOB_CACHE_BYTES[0] -= len(old)


_PNG_CACHE: "OrderedDict[tuple, bytes]" = OrderedDict()
_PNG_CACHE_BYTES = [0]
_PNG_CACHE_MAX = 64 * 1024 * 1024


def _page_png(owner: str, bid: str, page_index: int, scale: float) -> bytes:
    key = (owner, bid, page_index, scale)
    with _CACHE_LOCK:
        hit = _PNG_CACHE.get(key)
        if hit is not None:
            _PNG_CACHE.move_to_end(key)
            return hit
    png = P.render_page(_get_blob(owner, bid), page_index, scale)
    with _CACHE_LOCK:
        _PNG_CACHE[key] = png
        _PNG_CACHE_BYTES[0] += len(png)
        while _PNG_CACHE_BYTES[0] > _PNG_CACHE_MAX and _PNG_CACHE:
            _, old = _PNG_CACHE.popitem(last=False)
            _PNG_CACHE_BYTES[0] -= len(old)
    return png


def _quant_scale(scale) -> float:
    try:
        s = float(scale)
    except Exception:
        s = 1.5
    s = max(0.5, min(s, 2.5))
    return round(s * 4) / 4.0


# ------------------------------------------------------------------------------------------------- audit trail
def _chain_hash(prev: Optional[str], body: dict) -> str:
    payload = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(((prev or "GENESIS") + "|" + payload).encode("utf-8")).hexdigest()


def _event(env: dict, event: str, actor: str, meta: Optional[dict] = None, rid: Optional[str] = None,
           detail: Optional[dict] = None) -> None:
    events = env.setdefault("events", [])
    if event in _NOISY_EVENTS and len(events) >= MAX_EVENTS:
        return                          # lifecycle + owner events are never dropped
    prev = events[-1]["hash"] if events else None
    body = {"seq": len(events) + 1, "ts": _now(), "event": event, "actor": (actor or "")[:200],
            "recipient_id": rid, "ip": (meta or {}).get("ip") or None, "ua": (meta or {}).get("ua") or None,
            "detail": detail or None, "prev": prev}
    body["hash"] = _chain_hash(prev, {k: v for k, v in body.items()})
    events.append(body)


def _verify_chain(env: dict) -> dict:
    prev, broken = None, []
    events = env.get("events") or []
    for e in events:
        body = {k: v for k, v in e.items() if k != "hash"}
        if e.get("prev") != prev or e.get("hash") != _chain_hash(prev, body):
            broken.append(e.get("seq"))
        prev = e.get("hash")
    return {"ok": not broken, "count": len(events), "broken_at": broken}


# ------------------------------------------------------------------------------------------------- links
_DEV_KEY = secrets.token_bytes(32)
_WARNED_KEY = [False]


def _link_key() -> bytes:
    """HMAC key for signing links and gate cookies, from ESIGN_SECRET. Without it (development only) a random key per
    process is used: every link dies on restart, and in production (ESIGN_ENV=production) nothing can be sent."""
    k = (os.environ.get("ESIGN_SECRET") or "").strip()
    if k:
        return hashlib.sha256(b"esign-links|" + k.encode()).digest()
    if not _WARNED_KEY[0]:
        _WARNED_KEY[0] = True
        print("WARNING: ESIGN_SECRET is not set — signing links use a random per-process key and stop working on "
              "restart. Set ESIGN_SECRET (e.g. `openssl rand -hex 32`) before real use.")
    return _DEV_KEY


def _key_is_public_fallback() -> bool:
    return not (os.environ.get("ESIGN_SECRET") or "").strip()


def _mac(eid: str, rid: str, v: int) -> str:
    return hmac.new(_link_key(), f"esign|{eid}|{rid}|{int(v)}".encode(), hashlib.sha256).hexdigest()[:32]


def _token(eid: str, r: dict) -> str:
    v = int(r.get("link_version") or 1)
    return f"{eid}.{r['id']}.{v}.{_mac(eid, r['id'], v)}"


def _parse_token(tok: str):
    try:
        eid, rid, vs, mac = (tok or "").split(".")
    except ValueError:
        return None
    if not _HEX32.match(eid) or not _RID.match(rid) or not _VER.match(vs) or not _MAC.match(mac):
        return None
    v = int(vs)
    if not hmac.compare_digest(mac, _mac(eid, rid, v)):
        return None
    return eid, rid, v


def _ac_hash(salt: str, code: str) -> str:
    return hashlib.sha256((salt + "|" + code).encode("utf-8")).hexdigest()


def _ac_cookie_value(eid: str, r: dict) -> str:
    return hmac.new(_link_key(), f"ac|{eid}|{r['id']}|{r.get('link_version') or 1}|{r.get('ac_hash')}".encode(),
                    hashlib.sha256).hexdigest()[:40]


def _ac_cookie_name(r: dict) -> str:
    return "esign_ac_" + r["id"][4:]


def _ac_ok(env: dict, r: dict, meta: dict) -> bool:
    if not r.get("ac_hash"):
        return True
    got = (meta.get("cookies") or {}).get(_ac_cookie_name(r)) or ""
    return bool(got) and hmac.compare_digest(got, _ac_cookie_value(env["id"], r))


def _ec_cookie_name(r: dict) -> str:
    return "esign_ec_" + r["id"][4:]


def _ec_cookie_value(eid: str, r: dict) -> str:
    return hmac.new(_link_key(), f"ec|{eid}|{r['id']}|{r.get('link_version') or 1}|{r.get('ec_grant')}".encode(),
                    hashlib.sha256).hexdigest()[:40]


def _ec_ok(env: dict, r: dict, meta: dict) -> bool:
    """Email one-time code gate: passed in this browser (a cookie bound to the latest successful code)."""
    if not r.get("ec_required"):
        return True
    if not r.get("ec_grant"):
        return False
    got = (meta.get("cookies") or {}).get(_ec_cookie_name(r)) or ""
    return bool(got) and hmac.compare_digest(got, _ec_cookie_value(env["id"], r))


def _pending_gate(env: dict, r: dict, meta: dict) -> Optional[str]:
    """The first check this browser still has to pass before seeing the documents, in order: the access code the
    sender shared, then a one-time code emailed to the recipient. None when all are passed."""
    if not _ac_ok(env, r, meta):
        return "access_code"
    if not _ec_ok(env, r, meta):
        return "email_code"
    return None


def _granted(env: dict, r: dict, meta: dict) -> bool:
    return _pending_gate(env, r, meta) is None


def smtp_configured() -> bool:
    return bool((os.environ.get("ESIGN_SMTP_HOST") or "").strip())


def _from_addr() -> str:
    from email.utils import parseaddr
    return parseaddr(os.environ.get("ESIGN_SMTP_FROM") or "")[1] or "esign@localhost"


def _send_mail(to: str, subject: str, body: str, attachments: list | None = None, reply_to: str | None = None,
               sender: str | None = None, html: str | None = None, cc: list | None = None) -> None:
    """Send one plain-text email through the configured SMTP server (ESIGN_SMTP_*).
    attachments: [(filename, bytes, "type/subtype")]. Raises on failure; the caller reports it."""
    import smtplib
    from email.message import EmailMessage
    from email.utils import formatdate, make_msgid, parseaddr
    m = EmailMessage()
    m["Subject"], m["To"] = subject, to
    m["From"] = sender or os.environ.get("ESIGN_SMTP_FROM") or "esign@localhost"
    # our own Message-ID (on the sender's domain) and Date: without them the receiving server adds its own, which
    # counts against us with spam filters
    m["Message-ID"] = make_msgid(domain=parseaddr(str(m["From"]))[1].rpartition("@")[2] or "localhost")
    m["Date"] = formatdate(localtime=False, usegmt=True)
    if reply_to:
        m["Reply-To"] = reply_to
    if cc:
        m["Cc"] = ", ".join(cc)
    m.set_content(body)
    if html:                                     # plain text first, the HTML version as the alternative
        m.add_alternative(html, subtype="html")
    for name, data, ctype in attachments or []:
        main, _, sub = (ctype or "application/octet-stream").partition("/")
        m.add_attachment(data, maintype=main, subtype=sub or "octet-stream", filename=name)
    port = int(os.environ.get("ESIGN_SMTP_PORT") or "587")
    user = os.environ.get("ESIGN_SMTP_USER")
    # ESIGN_SMTP_TLS: "ssl" (implicit TLS, the default on port 465), "starttls" (the default otherwise: upgraded
    # whenever we log in or the server offers it), or "none" (a trusted local relay). ESIGN_SMTP_HELO names this
    # server in EHLO, since some relays refuse a container's random hostname.
    tls = (os.environ.get("ESIGN_SMTP_TLS") or ("ssl" if port == 465 else "starttls")).strip().lower()
    cls = smtplib.SMTP_SSL if tls == "ssl" else smtplib.SMTP
    with cls(os.environ["ESIGN_SMTP_HOST"], port, timeout=20,
             local_hostname=(os.environ.get("ESIGN_SMTP_HELO") or "").strip() or None) as srv:
        if tls != "ssl":
            srv.ehlo()
            if tls == "starttls" and (user or srv.has_extn("starttls")):
                srv.starttls()
                srv.ehlo()
        if user:
            srv.login(user, os.environ.get("ESIGN_SMTP_PASS", ""))
        srv.send_message(m)


def _mask_email(e: str) -> str:
    local, _, dom = (e or "").partition("@")
    if not dom:
        return ""
    return (local[:1] + "•" * max(2, min(6, len(local) - 1))) + "@" + dom


# ------------------------------------------------------------------------------------------------- email delivery
# When an envelope is sent, the owner chooses whether the server emails the links (env["mail"] = {"on": True, "base":
# <public URL the links point at>}); otherwise the owner shares them by hand and no email of any kind is sent.
# Every change that owes someone an email (a recipient's turn, a reminder, completion, a void, a note to the sender)
# appends a job to env["outbox"] in the same save as the change, so a restart loses nothing. _deliver() claims a few
# due jobs at a time under the envelope lock, sends them WITHOUT the lock, then records each result: the recipient's
# email state plus an "emailed" / "email_failed" event in the audit trail. A failed send is retried (MAIL_TRIES
# attempts, MAIL_BACKOFF apart) by main.py's delivery loop (deliver_due()); notes to the sender are not part of the
# signing record. Emailing links is opt-in per server: ESIGN_MAIL=1 plus ESIGN_SMTP_HOST (the email one-time-code
# step only needs ESIGN_SMTP_HOST).
_MAIL_PENDING: dict = {}                            # envelope id -> owner, for envelopes with queued email
_MAIL_UNRECORDED: dict = {}                         # envelope id -> results a database error kept us from saving
_MAIL_GUARD = threading.Lock()
_MAIL_SCANNED = [0.0]                               # when the delivery loop last read every outbox (0 = never)
_CAPS_REBUILT: set = set()                          # owners whose last-day email counts were re-read after start-up
_STARTED = time.time()
_OWNER_KINDS = ("owner_signed", "owner_declined", "owner_completed", "owner_failed")
_LINK_KINDS = ("invite", "remind")
# what an address must look like before we email it: one plain mailbox (no comments, groups or lists, which a
# To header would read as several recipients)
_MAILABLE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
                       r"@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$")
_FILLERS = {"ᅟ", "ᅠ", "⠀", "ㅤ", "ﾠ", "឴", "឵", "᠎"}


class _MailQuota(Exception):
    def __init__(self, why: str, retry_at: float):
        super().__init__(why)
        self.retry_at = retry_at


class _MailBad(Exception):
    pass


def mail_available() -> bool:
    """This server emails envelope links: outgoing mail is set up AND it is switched on here (ESIGN_MAIL=1)."""
    return smtp_configured() and (os.environ.get("ESIGN_MAIL") or "").strip() == "1"


def _mail_on(env: dict) -> bool:
    return bool((env.get("mail") or {}).get("on"))


def _mailable(addr: str) -> bool:
    from email.utils import parseaddr
    a = (addr or "").strip()
    return len(a) <= 254 and "=?" not in a and bool(_MAILABLE.match(a)) and parseaddr(a)[1] == a


def _mailbox_key(addr: str) -> str:
    """One inbox, however it's spelled: no +tag, and Gmail ignores dots. Only for counting; mail goes to `addr`."""
    local, _, dom = (addr or "").strip().lower().rpartition("@")
    local = local.split("+", 1)[0]
    if dom in ("gmail.com", "googlemail.com"):
        local, dom = local.replace(".", ""), "gmail.com"
    return f"{local}@{dom}"


def _plain(s, n: int = 120) -> str:
    """Sender-written text for a header or a single line: compatibility-normalised (a full-width ＠ becomes @),
    without control, format or blank 'filler' characters, whitespace collapsed."""
    import unicodedata
    s = unicodedata.normalize("NFKC", str(s or ""))
    out = []
    for ch in s:
        cat = unicodedata.category(ch)
        if ch in _FILLERS or cat in ("Cf", "Co", "Cn", "Cs"):
            continue
        out.append(" " if cat in ("Cc", "Zs", "Zl", "Zp") else ch)
    # "=?charset?b?...?=" would be decoded by mail clients (an encoded word): keep it literal text
    return re.sub(r" +", " ", "".join(out)).replace("=?", "= ?").strip()[:n].strip()


def _display_from(name: str = "") -> str:
    """'Jane Smith via <Brand> <esign@…>': the sender's name as a plain display name (no address-like characters),
    our own address (mail relays only send as their own domain)."""
    from email.headerregistry import Address
    addr = _from_addr()
    bn = _plain(brand.name(), 60) or "E-Sign"
    nm = re.sub(r"[\"<>@,;:\\()\[\]]+", " ", _plain(name, 80))
    nm = re.sub(r" +", " ", nm).strip()[:60].strip()
    disp = f"{nm} via {bn}" if nm and nm.lower() != bn.lower() else bn
    try:
        return str(Address(display_name=disp, addr_spec=addr))
    except Exception:
        return addr


def public_url() -> str:
    """ESIGN_PUBLIC_URL without a trailing slash ('' when unset)."""
    return (os.environ.get("ESIGN_PUBLIC_URL") or "").strip().rstrip("/")


def _link_base(request: Optional[Request] = None, owner: str = "") -> str:
    """The site an envelope's emailed links point at: ESIGN_PUBLIC_URL. Without it, only a local development host
    (localhost / 127.0.0.1 / *.localhost / the test client) is taken from the request — never an arbitrary Host
    header, which an attacker could set to make our emails link to their site. '' = unknown (don't email)."""
    base = public_url()
    if base:
        return base
    try:
        netloc = (request.url.netloc if request is not None else "").lower()
        hostname, port = (request.url.hostname or "").lower(), request.url.port
    except Exception:
        netloc, hostname, port = "", "", None
    if netloc and "@" not in netloc and re.match(r"^(localhost|127\.0\.0\.1|testserver|[a-z0-9-]+\.localhost)$",
                                                 hostname or ""):
        return f"{request.url.scheme}://{hostname}" + (f":{int(port)}" if port else "")
    return ""


def _owner_home(env: dict) -> str:
    base = (env.get("mail") or {}).get("base") or public_url()
    return base + "/#envelope/" + env["id"]


def _greeting_name(name) -> str:
    """Who "Hello …," addresses: the first word of the name (as the owner app's mail draft does), "Dr Georgiou" when
    the name starts with a title, and "Maria" for "Georgiou, Maria"."""
    parts = _plain(name, 80).split()
    if not parts:
        return ""
    if parts[0].rstrip(".").lower() in ("mr", "mrs", "ms", "miss", "mx", "dr", "prof", "professor", "sir", "madam",
                                        "dame", "lord", "lady", "rev", "hon"):
        return f"{parts[0]} {parts[-1]}" if len(parts) > 1 else parts[0]
    if parts[0].endswith(",") and len(parts) > 1:
        return parts[1].rstrip(",")
    return parts[0]


def _mail_filename(title) -> str:
    """The attached PDF's name: the title as written (— × é stay; mail clients show them), minus what a file name
    can't hold."""
    base = re.sub(r"[\\/:*?\"<>|]+", " ", _plain(title, 100))
    base = re.sub(r" +", " ", base).strip(" .")
    return (base or "document") + " - signed.pdf"


def _fmt_when(iso) -> str:
    d = _parse_iso(iso)
    return f"{d.day} {d:%b %Y, %H:%M} UTC" if d else ""


def _queue_mail(env: dict, kind: str, rid: Optional[str] = None) -> bool:
    """Owe an email (the caller saves the envelope); True if it was queued. An unsent link email to the same
    recipient is replaced, so a recipient never gets two at once. Notes to the sender need the sender's address, and
    "we couldn't email" notes come as one note listing everyone, at most MAIL_FAILNOTE_DAY a day per envelope."""
    if not _mail_on(env) or not mail_available():
        return False
    if kind in _OWNER_KINDS and not env.get("sender_email"):
        return False
    ob = env.setdefault("outbox", [])
    if kind == "owner_failed":
        if any(j.get("kind") == "owner_failed" and not j.get("sending") for j in ob):
            return True                             # the note that's waiting will list this one too
        try:
            _mq_take([(f"esm-failnote:{env.get('id')}", MAIL_FAILNOTE_DAY, "notes")])
        except _MailQuota:
            return False
        rid = None
    if kind in _LINK_KINDS:
        replaced = [j for j in ob if j.get("rid") == rid and j.get("kind") in _LINK_KINDS and not j.get("sending")]
        if kind == "remind" and any(j.get("kind") == "invite" for j in replaced):
            kind = "invite"                         # the first link email never went out: still an invitation
        ob[:] = [j for j in ob if j not in replaced]
    if len(ob) >= MAIL_OUTBOX_MAX:
        print(f"esign: outbox full for envelope {env.get('id')}; {kind} email not queued")
        return False
    t = _now()
    ob.append({"id": "ml_" + _hex(5), "kind": kind, "rid": rid, "at": t, "next": t, "tries": 0})
    r = _recip(env, rid) if rid and kind not in _OWNER_KINDS else None
    if r is not None:
        r["email_state"] = "queued"
        r.pop("email_error", None)
        r.pop("email_held", None)
    if env.get("id"):
        with _MAIL_GUARD:
            _MAIL_PENDING[env["id"]] = env["owner"]
    return True


def _job_live(env: dict, j: dict) -> bool:
    """Is this queued email still worth sending? (A link email for someone who has since finished, or for an
    envelope that was voided, declined or expired, is dropped; so is a "we couldn't email" note once nobody's email
    is failing any more.)"""
    k, st = j.get("kind"), env.get("status")
    if k == "owner_failed":
        return bool(env.get("sender_email")) and any(_failing(r) for r in env.get("recipients") or [])
    if k in _OWNER_KINDS:
        return bool(env.get("sender_email"))
    r = _recip(env, j.get("rid") or "")
    if not r:
        return False
    if k == "invite":
        return st == "sent" and r.get("status") in ("sent", "notified", "viewed")
    if k == "remind":
        return st == "sent" and r.get("role") in ACTORS and r.get("status") in ("sent", "notified", "viewed")
    if k == "completed":
        return st == "completed" and bool(env.get("final"))
    if k == "voided":
        return st == "voided"
    return False


def _failing(r: dict) -> bool:
    """An email failure that still matters: the signed copy or void notice didn't arrive, or the current link
    hasn't reached them (not shared by hand since, not signed)."""
    if r.get("email_state") != "failed":
        return False
    if r.get("email_failed_kind") in ("completed", "voided"):
        return True
    return r.get("status") in ("sent", "viewed") and not r.get("notified_at")


def _sync_email_states(env: dict) -> None:
    """A recipient shown as 'queued' with nothing left in the outbox goes back to what it was."""
    waiting = {j.get("rid") for j in env.get("outbox") or [] if j.get("kind") not in _OWNER_KINDS}
    for r in env.get("recipients") or []:
        if r.get("email_state") == "queued" and r["id"] not in waiting:
            r["email_state"] = "sent" if r.get("emailed_at") else None


def _copy_by_link(r: dict) -> bool:
    """Recipients the sender protected with an access code get the completed copy as a link (an attachment would
    skip that check)."""
    return bool(r.get("ac_hash"))


def _copy_mode(env: dict, r: dict):
    """How this recipient will get the completed copy: 'attach' (the PDF), 'link', or False (not emailed)."""
    if not _mail_on(env) or not mail_available():
        return False
    fin = env.get("final") or {}
    size = int(fin.get("size") or 0) if fin else sum(int(d.get("size") or 0) for d in env.get("documents") or [])
    return "link" if _copy_by_link(r) or size > MAIL_ATTACH_MAX else "attach"


def _attach_ok(env: dict, r: dict) -> bool:
    fin = env.get("final") or {}
    return bool(fin.get("blob_id")) and int(fin.get("size") or 0) <= MAIL_ATTACH_MAX and not _copy_by_link(r)


def _gate_lines(env: dict, r: dict, who: str) -> list:
    out = []
    if r.get("ac_hash"):
        out.append(f"You'll need an access code to open it. {who} will give it to you separately; it isn't in this "
                   f"email.")
    if r.get("ec_required"):
        out.append("When you open the link, we'll email you a one-time code to confirm it's you.")
    if env.get("expires_at"):
        out.append(f"The link works until {_fmt_when(env.get('expires_at'))}.")
    return out


def _render_mail(env: dict, j: dict):
    """(to, subject, body, attachments, reply_to, sender, link_version) for one queued email, or None to drop it.
    Plain text; the title, message and names come from the sender and are never treated as markup."""
    k = j.get("kind")
    title = _plain(env.get("title"), 120) or "documents"
    who = _plain(env.get("sender_name"), 80) or "The sender"
    bn = _plain(brand.name(), 60) or "E-Sign"
    foot = ["", "—", f"Sent by {bn} for {who}. The title and any message above were written by {who}."]
    if k in _OWNER_KINDS:
        to = (env.get("sender_email") or "").strip()
        if not _mailable(to):
            raise _MailBad("the sender's address isn't one we can email")
        r = _recip(env, j.get("rid") or "") or {}
        name = _plain(r.get("name"), 80) or "A recipient"
        masked = _mask_email(r.get("email") or "")
        actors = [x for x in env.get("recipients") or [] if x.get("role") in ACTORS]
        done = sum(1 for x in actors if x.get("status") == "signed")
        home = _owner_home(env)
        if k == "owner_signed":
            verb = "reviewed" if r.get("role") == "viewer" else "signed"
            subject = f"{name} {verb} “{title}”"
            body = [f"{name} ({masked}) {verb} “{title}”.", "",
                    f"{done} of {len(actors)} {'person has' if len(actors) == 1 else 'people have'} finished."]
            nxt = [_plain(x.get("name"), 80) for x in actors if x.get("status") in ("sent", "notified", "viewed")]
            if nxt:
                body.append("Waiting for: " + ", ".join(nxt[:6]) + (f" and {len(nxt) - 6} more" if len(nxt) > 6
                                                                     else "") + ".")
        elif k == "owner_declined":
            subject = f"{name} declined “{title}”"
            body = [f"{name} ({masked}) declined to sign “{title}”. Their reason is in the envelope.", "",
                    "The envelope is now closed, so nobody else can sign it. To try again, duplicate it in "
                    "E-Sign and send the copy."]
        elif k == "owner_completed":
            subject = f"Completed: {title}"
            body = [f"Everyone has signed “{title}”.", "",
                    "The signed PDF, with its Certificate of Completion, is ready to download in E-Sign."]
        else:                                       # owner_failed: everyone whose email is failing now
            failed = [x for x in env.get("recipients") or [] if _failing(x)]
            if not failed:
                return None
            what = {"completed": "the signed copy", "voided": "the void notice"}
            subject = (f"We couldn't email {_plain(failed[0].get('name'), 80) or 'a recipient'}" if len(failed) == 1
                       else f"We couldn't email {len(failed)} recipients")
            body = [f"We couldn't email these people about “{title}”:", ""]
            body += [f"- {_plain(x.get('name'), 80) or 'A recipient'} ({_mask_email(x.get('email') or '')}): "
                     f"{what.get(x.get('email_failed_kind'), 'the link')} — {x.get('email_error') or 'not delivered'}"
                     for x in failed[:20]]
            body += ["", "Check each address (correcting it in E-Sign sends a new link). Then send it again from the "
                     "envelope (for someone who receives a copy, regenerate their link), or copy the link and send "
                     "it yourself."]
        body += ["", "Open the envelope: " + home, "", "—", f"{bn}. You get these emails because your "
                 "address is set as the sender's email on this envelope."]
        return to, subject, "\n".join(body), None, None, _display_from(""), None
    r = _recip(env, j.get("rid") or "")
    if not r:
        return None
    if not _mailable(r.get("email") or ""):
        raise _MailBad("the address isn't one we can email")
    lv = int(r.get("link_version") or 1)
    url = f"{(env.get('mail') or {}).get('base') or ''}/sign/{_token(env['id'], r)}"
    name = _greeting_name(r.get("name"))
    reply = env.get("sender_email") if _mailable(env.get("sender_email") or "") else None
    body = [f"Hello {name}," if name else "Hello,", ""]
    attach = None
    if k in _LINK_KINDS:
        role = r.get("role")
        if role == "cc":
            subject = f"{who} sent you a copy of “{title}”"
            body += [f"{who} sent you “{title}” for your records. You don't need to do anything: once everyone has "
                     f"signed, we'll email you " + ("a link to the signed copy." if _copy_by_link(r) else
                                                    "the signed copy."), ""]
        else:
            act = "review" if role == "viewer" else "sign"
            subject = ("Reminder: " if k == "remind" else "") + f"Please {act}: {title}"
            body += [(f"This is a reminder that {who} is waiting for you to {act} “{title}”." if k == "remind" else
                      f"{who} sent you “{title}” to {act}."), ""]
        msg = (env.get("message") or "").strip()
        if msg:
            body += [f"Message from {who}:"] + msg.splitlines()[:40] + [""]
        note = (r.get("note") or "").strip()
        if note:
            body += ["A note for you:"] + note.splitlines()[:20] + [""]
        body += [{"cc": "You can look at it here:", "viewer": "Review it here:"}.get(role, "Review and sign here:"), url]
        extra = _gate_lines(env, r, who)
        if extra:
            body += [""] + extra
        body += ["", "This link is just for you, so please don't forward this email."]
    elif k == "completed":
        subject = f"Completed: {title}"
        body += [f"Everyone has signed “{title}”.", ""]
        if _attach_ok(env, r):
            data = _get_blob(env["owner"], env["final"]["blob_id"])
            attach = [(_mail_filename(env.get("title")), data, "application/pdf")]
            body += ["The signed PDF is attached, with its Certificate of Completion at the end. You can also "
                     "download it from your signing link:", url]
        else:
            body += ["Download the signed PDF, with its Certificate of Completion, from your signing link:", url]
            if r.get("ac_hash"):
                body += ["", f"You'll need the same access code as before; {who} can give it to you again."]
        body += ["", "Please keep a copy for your records."]
    elif k == "voided":
        subject = f"Voided: {title}"
        body += [f"{who} has voided “{title}”, so it no longer needs anything from you."]
        why = _plain(env.get("void_reason"), 500)
        if why and why != "Voided by sender":
            body += ["", f"Reason given: {why}"]
    else:
        return None
    body.append(f"Questions about it? Reply to this email to reach {who}." if reply else
                f"Questions about it? Please contact {who} directly.")
    body += foot + ["If you weren't expecting this email, you can ignore it."]
    return r["email"].strip(), subject, "\n".join(body), attach, reply, _display_from(env.get("sender_name") or ""), lv


# ---- daily email caps: their own store (never evicted by the per-IP minute buckets of _rate_ok)
_MQ: dict = {}
_MQ_LOCK = threading.Lock()


def _mq_check(limits, window: int = 86400) -> None:
    """Raise _MailQuota (with when the earliest blocking window frees up) if any (key, limit, why) is full."""
    now = time.time()
    with _MQ_LOCK:
        if len(_MQ) > 50000:                        # forget keys with nothing left in their window
            for key in [k for k, q in _MQ.items() if not q or q[-1] < now - window]:
                _MQ.pop(key, None)
        for key, limit, why in limits:
            q = _MQ.setdefault(key, deque())
            while q and q[0] < now - window:
                q.popleft()
            if len(q) >= limit:
                raise _MailQuota(why, q[len(q) - limit] + window + 1)


def _mq_add(limits, at: Optional[float] = None) -> None:
    with _MQ_LOCK:
        for key, _limit, _why in limits:
            q = _MQ.setdefault(key, deque())
            q.append(at if at is not None else time.time())
            if at is not None and len(q) > 1 and q[-2] > q[-1]:
                _MQ[key] = deque(sorted(q))


def _mq_take(limits, window: int = 86400) -> None:
    """Check, then count one against every limit (reminders, re-issued links, failure notes)."""
    _mq_check(limits, window)
    _mq_add(limits)


def _mail_limits(owner: str, to: str, kind: str) -> list:
    """Per account (ESIGN_MAIL_DAILY_CAP), per server, per inbox across accounts, and per (account, inbox) —
    one account can't use up another's allowance to an address. Counted only when an email actually goes out."""
    box = _mailbox_key(to)
    out = [(f"esm-owner:{owner}", MAIL_OWNER_DAY, "the daily email limit for this account was reached"),
           ("esm-global", MAIL_GLOBAL_DAY, "this server's daily email limit was reached"),
           (f"esm-addr:{box}", MAIL_ADDR_DAY, "this address has had today's limit of emails")]
    if kind in _OWNER_KINDS:
        out.append((f"esm-note:{owner}:{box}", MAIL_NOTE_DAY, "the daily limit of notes to the sender was reached"))
    else:
        out.append((f"esm-to:{owner}:{box}", MAIL_TO_DAY, "this address has had today's limit of emails from you"))
    return out


def _mail_reason(e) -> tuple:
    """(plain reason, permanent?) for a failed send. A 4xx answer is a 'try later'; only a 5xx is final."""
    import smtplib
    import socket
    if isinstance(e, _MailQuota):
        return str(e), False
    if isinstance(e, _MailBad):
        return str(e), True
    if isinstance(e, smtplib.SMTPRecipientsRefused):
        codes = [int(c) for c, _m in (getattr(e, "recipients", None) or {}).values() if str(c).isdigit()] or [550]
        if all(c >= 500 for c in codes):
            return f"the mail server refused the address ({codes[0]})", True
        return f"the mail server asked to try later ({codes[0]})", False
    if isinstance(e, smtplib.SMTPResponseException):
        code = int(getattr(e, "smtp_code", 0) or 0)
        if 500 <= code < 600:
            return f"the mail server said no ({code})", True
        return f"the mail server asked to try later ({code})", False
    if isinstance(e, (smtplib.SMTPException, socket.timeout, TimeoutError, OSError)):
        return "the mail server didn't answer", False
    return f"the email couldn't be prepared ({type(e).__name__})", False


def _stale_link_job(env: dict, j: dict, msg) -> bool:
    """A link email made for an address or link that has since changed (corrected, re-issued): from what was
    rendered, or, when rendering failed, from what the job was claimed for."""
    if j.get("kind") not in _LINK_KINDS:
        return False
    if isinstance(msg, tuple):
        addr, lv = msg[0], msg[6]
    elif j.get("for"):
        addr, lv = j["for"]
    else:
        return False
    r = _recip(env, j.get("rid") or "")
    return not r or (r.get("email") or "").strip().lower() != str(addr).lower() or \
        int(r.get("link_version") or 1) != int(lv)


def _mail_done(env: dict, j: dict, msg: tuple) -> None:
    k = j.get("kind")
    if k in _OWNER_KINDS:
        return
    r = _recip(env, j.get("rid") or "")
    if not r:
        return
    t, masked = _now(), _mask_email(msg[0])
    what = "copy link" if r.get("role") == "cc" else ("reminder with the signing link" if k == "remind"
                                                      else "signing link")
    if _stale_link_job(env, j, msg):                # history only: it says nothing about the current link
        _event(env, "emailed", "system", None, r["id"],
               {"note": f"{what} emailed to {masked} (that link or address has since been replaced)"})
        return
    r["emailed_at"] = t
    r["email_count"] = int(r.get("email_count") or 0) + 1
    r["email_state"] = "sent"
    for key in ("email_error", "email_failed_at", "email_failed_kind", "email_held"):
        r.pop(key, None)
    if k in _LINK_KINDS:
        r["link_emailed_at"] = r.get("link_emailed_at") or t
        r["notified_at"] = r.get("notified_at") or t
        if r.get("status") == "sent":
            r["status"] = "notified"
        note = f"{what} emailed to {masked}"
        ob = env.get("outbox") or []                # they have the current link: an unsent repeat is dropped
        ob[:] = [x for x in ob if not (x.get("rid") == r["id"] and x.get("kind") in _LINK_KINDS
                                       and x.get("id") != j.get("id") and not x.get("sending"))]
        if env.get("status") == "voided" and not any(x.get("kind") == "voided" and x.get("rid") == r["id"]
                                                     for x in ob):
            _queue_mail(env, "voided", r["id"])     # voided while this was on its way: tell them it's off
    elif k == "completed":
        note = f"completed copy emailed to {masked}" + (" with the signed PDF attached" if msg[3] else "")
    else:
        note = f"void notice emailed to {masked}"
    _event(env, "emailed", "system", None, r["id"], {"note": note})


def _mail_failed(env: dict, j: dict, why: str, msg=None) -> None:
    k = j.get("kind")
    if k in _OWNER_KINDS:
        print(f"esign: note to the sender of {env.get('id')} not sent ({k}): {why}")
        return
    r = _recip(env, j.get("rid") or "")
    if not r:
        return
    what = {"invite": "the link", "remind": "the reminder", "completed": "the completed copy",
            "voided": "the void notice"}.get(k, "an email")
    tried = msg[0] if isinstance(msg, tuple) else ((j.get("for") or [None])[0] or r.get("email") or "")
    if _stale_link_job(env, j, msg):
        _event(env, "email_failed", "system", None, r["id"],
               {"note": f"{what} couldn't be emailed to {_mask_email(tried)}: {why} (that link or address has "
                        f"since been replaced)"})
        return
    r["email_state"], r["email_error"], r["email_failed_at"], r["email_failed_kind"] = "failed", why, _now(), k
    r.pop("email_held", None)
    _event(env, "email_failed", "system", None, r["id"],
           {"note": f"{what} couldn't be emailed to {_mask_email(tried)}: {why}"})
    if k in _LINK_KINDS:
        _queue_mail(env, "owner_failed")


def _record(env: dict, items) -> int:
    """Apply send results [(claim, job, error, rendered)] to the envelope (the caller holds its lock and saves).
    Returns how many went out."""
    ob = env.setdefault("outbox", [])
    sent = 0
    for claim, j, err, msg in items:
        cur = next((x for x in ob if x.get("id") == j["id"]), None)
        if cur is not None and cur.get("claim") != claim:
            cur = None                              # someone else has claimed it since (ours looked lost)
        if err is None and msg is not None:
            sent += 1
            if cur is not None:
                ob.remove(cur)
            _mail_done(env, j, msg)
            continue
        if err is None or cur is None:              # nothing to send any more / dropped meanwhile
            if cur is not None:
                ob.remove(cur)
            continue
        why, permanent = _mail_reason(err)
        if j.get("kind") in _LINK_KINDS and any(x is not cur and x.get("rid") == j.get("rid")
                                                and x.get("kind") in _LINK_KINDS for x in ob):
            ob.remove(cur)                          # a newer email for this recipient replaces it
            continue
        if _stale_link_job(env, j, msg):            # its link or address was replaced: history only
            ob.remove(cur)
            _mail_failed(env, j, why, msg)
            continue
        quota = isinstance(err, _MailQuota)
        tries = int(cur.get("tries") or 0) + (0 if quota else 1)
        if not permanent and tries < MAIL_TRIES:
            for key in ("sending", "claim", "for"):
                cur.pop(key, None)
            wait = (err.retry_at - time.time()) if quota else MAIL_BACKOFF[min(tries, len(MAIL_BACKOFF)) - 1]
            cur.update(tries=tries, err=why, next=_iso(_now_dt() + _dt.timedelta(seconds=max(30, wait))))
            r = _recip(env, j.get("rid") or "") if j.get("kind") not in _OWNER_KINDS else None
            if r is not None:
                r["email_error"] = why
                if quota:
                    r["email_held"] = True        # waiting on a daily limit: the owner may share it meanwhile
            print(f"esign: email ({j.get('kind')}) for {env.get('id')} not sent, will retry ({tries}/{MAIL_TRIES}): "
                  f"{why}")
            continue
        ob.remove(cur)
        _mail_failed(env, j, why, msg)
    return sent


def _deliver(eid: str, owner: str) -> int:
    """Send this envelope's due emails; returns how many went out. Jobs are claimed MAIL_CHUNK at a time, and the
    envelope lock is never held while talking to the mail server (a slow relay must not stall signers). Results a
    database error kept from being saved are kept in memory and applied first next time, so nothing is re-sent."""
    if not mail_available():
        return 0
    sent = 0
    for _round in range(1 + MAIL_OUTBOX_MAX // MAIL_CHUNK):
        claim, todo = _hex(4), []
        with _lock(eid):
            env = _load(eid, owner)
            if env is None:                         # gone, or the database didn't answer: try again later
                return sent
            with _MAIL_GUARD:
                held = _MAIL_UNRECORDED.pop(eid, None)
            changed = _check_expiry(env)
            if held:
                sent += _record(env, held)
                changed = True
            now, keep = _now_dt(), []
            for j in env.get("outbox") or []:
                if not _job_live(env, j):
                    changed = True
                    continue
                keep.append(j)
                busy = _parse_iso(j.get("sending"))
                nxt = _parse_iso(j.get("next"))
                if len(todo) >= MAIL_CHUNK or (busy and (now - busy).total_seconds() < MAIL_STALE) or \
                        (nxt and nxt > now):
                    continue
                try:
                    msg = _render_mail(env, j)
                except Exception as e:
                    if not isinstance(e, _MailBad):
                        print(f"esign: email for {eid} couldn't be prepared: {e!r}")
                    msg = e
                j["sending"], j["claim"] = _iso(now), claim
                r = _recip(env, j.get("rid") or "") if j.get("kind") in _LINK_KINDS else None
                if r is not None:                   # what this claim is for, if rendering failed
                    j["for"] = [(r.get("email") or "").strip(), int(r.get("link_version") or 1)]
                changed = True
                todo.append((dict(j), msg))
            env["outbox"] = keep
            _sync_email_states(env)
            if changed:
                try:
                    _save(env)
                except Exception:
                    if held:                        # not saved: keep those results for next time
                        with _MAIL_GUARD:
                            _MAIL_UNRECORDED.setdefault(eid, []).extend(held)
                    raise
            with _MAIL_GUARD:
                if keep:
                    _MAIL_PENDING[eid] = owner
                else:
                    _MAIL_PENDING.pop(eid, None)
        if not todo:
            return sent
        items = []
        for j, msg in todo:
            if msg is None or isinstance(msg, Exception):
                items.append((claim, j, msg, None))
                continue
            to, subject, body, attach, reply, sender, _lv = msg
            limits = _mail_limits(owner, to, j["kind"])
            try:
                _mq_check(limits)
                _send_mail(to, subject, body, attachments=attach, reply_to=reply, sender=sender)
                _mq_add(limits)                     # counted only when it actually went out
                items.append((claim, j, None, msg))
            except Exception as e:
                items.append((claim, j, e, msg))
        try:
            with _lock(eid):
                env = _load(eid, owner)
                if env is None:
                    raise RuntimeError("envelope not readable")
                sent += _record(env, items)
                _sync_email_states(env)
                _save(env)
                with _MAIL_GUARD:
                    if env["outbox"]:
                        _MAIL_PENDING[eid] = owner
                    else:
                        _MAIL_PENDING.pop(eid, None)
        except Exception as e:
            with _MAIL_GUARD:                       # applied before anything is claimed again
                _MAIL_UNRECORDED.setdefault(eid, []).extend(items)
                _MAIL_PENDING[eid] = owner
            print(f"esign: couldn't record email results for {eid} yet ({type(e).__name__}); will retry")
            return sent
    return sent


def _deliver_safe(eid: str, owner: str) -> None:
    try:
        _deliver(eid, owner)
    except Exception as e:
        print(f"esign: email delivery for {eid} failed: {type(e).__name__}: {e}")


def _kick(env: dict, wait: float = 0.0) -> None:
    """Deliver an envelope's queued email now, in the background (an owner request waits up to `wait` seconds so
    its answer can show the result; a signer's request doesn't wait)."""
    if not env or not env.get("outbox") or not mail_available():
        return
    if MAIL_SYNC:
        _deliver_safe(env["id"], env["owner"])
        return
    t = threading.Thread(target=_deliver_safe, args=(env["id"], env["owner"]), name="esign-mail", daemon=True)
    t.start()
    if wait > 0:
        t.join(wait)


def deliver_due() -> int:
    """main.py's delivery loop: send what is due (retries included) in every envelope with queued email. Every
    outbox is re-read at start-up and then every MAIL_RESCAN (a scan the database didn't answer is retried a minute
    later); the first scan also re-counts the last day's emails, so a restart doesn't reset the daily caps."""
    if not mail_available():
        return 0
    if time.time() - _MAIL_SCANNED[0] >= MAIL_RESCAN:
        repo = _repo()
        owners = repo.list_pipeline_owners(PIPE_ENV) if hasattr(repo, "list_pipeline_owners") else []
        cutoff = _now_dt() - _dt.timedelta(days=1)
        complete = bool(owners)
        for owner in owners:
            rows = repo.list_documents(owner, pipeline=PIPE_ENV, limit=1_000_000) or []
            if not rows:                            # an owner of envelopes with none: the database didn't answer
                complete = False
                continue
            rebuild = owner not in _CAPS_REBUILT
            for row in rows:
                env = row.get("review") or {}
                if not env.get("id"):
                    continue
                if env.get("outbox") or env["id"] in _MAIL_UNRECORDED:
                    with _MAIL_GUARD:
                        _MAIL_PENDING[env["id"]] = owner
                if rebuild and _mail_on(env):        # emails from before this process started (later ones counted)
                    for r in env.get("recipients") or []:
                        at = _parse_iso(r.get("emailed_at"))
                        if at and cutoff < at and at.timestamp() < _STARTED and r.get("email"):
                            _mq_add(_mail_limits(owner, r["email"], "invite"), at.timestamp())
            _CAPS_REBUILT.add(owner)
        _MAIL_SCANNED[0] = time.time() if complete else 0.0
    with _MAIL_GUARD:
        items = list(_MAIL_PENDING.items())
    n = 0
    for eid, owner in items:
        try:
            n += _deliver(eid, owner)
        except Exception as e:
            print(f"esign: email delivery for {eid} failed: {type(e).__name__}: {e}")
    return n


def ensure_pki(data_dir=None) -> Optional[dict]:
    """Start-up hook (main.py): with no ESIGN_SEAL_P12 and ESIGN_PKI_AUTO not "0", make sure DATA_DIR/pki holds a
    self-signed root + document seal (generated on first boot), so completed envelopes are sealed from the start.
    Never raises — a missing seal only means completions are unsealed (and say so)."""
    if (os.environ.get("ESIGN_SEAL_P12") or "").strip() or (os.environ.get("ESIGN_PKI_AUTO") or "").strip() == "0":
        return None
    try:
        from . import esign_pki as PKI
        return PKI.ensure_pki(data_dir)
    except Exception as e:
        print(f"E-Sign: couldn't prepare the seal certificate ({type(e).__name__}: {e}); completions stay unsealed")
        return None


# ------------------------------------------------------------------------------------------------- envelope model
def _blank_env(owner: str, title: str) -> dict:
    t = _now()
    return {"pipeline": PIPE_ENV, "id": None, "owner": owner, "title": title or "Untitled envelope", "message": "",
            "status": "draft", "sender_name": "", "sender_email": "", "signing_order": "sequential",
            "expires_at": None, "created_at": t, "updated_at": t, "sent_at": None, "completed_at": None,
            "voided_at": None, "void_reason": None, "decline": None, "current_order": None,
            "documents": [], "recipients": [], "fields": [], "events": [], "final": None}


def _recip(env: dict, rid: str) -> Optional[dict]:
    for r in env.get("recipients") or []:
        if r.get("id") == rid:
            return r
    return None


def _doc(env: dict, did: str) -> Optional[dict]:
    for d in env.get("documents") or []:
        if d.get("id") == did:
            return d
    return None


def _check_expiry(env: dict) -> bool:
    """Lazily flip a sent envelope to expired. Returns True if it changed (caller saves)."""
    if env.get("status") != "sent":
        return False
    exp = _parse_iso(env.get("expires_at"))
    if exp and _now_dt() > exp:
        env["status"] = "expired"
        _event(env, "expired", "system")
        return True
    return False


def _expire_and_save(env: dict) -> dict:
    if env.get("status") == "sent" and _parse_iso(env.get("expires_at")) and _now_dt() > _parse_iso(env["expires_at"]):
        with _lock(env["id"]):
            fresh = _load(env["id"], env["owner"]) or env
            if _check_expiry(fresh):
                _save(fresh)
            return fresh
    return env


def _role_label(role: str) -> str:
    return {"signer": "Needs to sign", "cc": "Receives a copy", "viewer": "Needs to view"}.get(role, role)


def _public_link_allowed(env: dict) -> bool:
    return env.get("status") in ("sent", "completed", "declined", "expired")


def _owner_view(env: dict) -> dict:
    v = copy.deepcopy(env)
    v.pop("pipeline", None)
    v.pop("outbox", None)
    v.pop("mail_ok", None)
    v["email_available"] = mail_available() and env.get("status") == "draft"
    for r in v.get("recipients") or []:             # nothing can be sending while email is off on this server
        if r.get("email_state") == "queued" and not mail_available():
            r["email_state"] = None
    v["mail"] = {"on": _mail_on(env), "base": (env.get("mail") or {}).get("base")} if env.get("mail") else None
    for r in v.get("recipients") or []:
        r["access_code_set"] = bool(r.get("ac_hash"))
        r["link"] = ("/sign/" + _token(env["id"], r)) if _public_link_allowed(env) else None
        r["access_locked"] = bool(r.get("ac_locked"))
        r["email_code"] = bool(r.get("ec_required"))
        r["email_verified_at"] = r.get("ec_verified_at")
        r["email_code_locked"] = bool(r.get("ec_locked"))
        r["signature_level"] = "simple" if r.get("status") == "signed" else None
        for k in ("ac_hash", "ac_salt", "ac_fail", "ac_lock_until", "ac_total_fail", "ac_locked", "ac_last_ok_at",
                  "sig_blob_id", "initials_blob_id", "ec_hash", "ec_salt", "ec_expires", "ec_fail", "ec_lock_until",
                  "ec_grant", "ec_sends", "ec_last_sent", "ec_required", "ec_verified_at", "ec_total_fail",
                  "ec_locked"):
            r.pop(k, None)
    for d in v.get("documents") or []:
        for k in ("blob_id", "original_blob_id", "working_blob_id"):
            d.pop(k, None)
    if v.get("final"):
        v["final"] = dict({k: v["final"].get(k) for k in ("sha256", "size", "pages", "cert_pages", "seal")},
                          certificate_sha256=(v["final"].get("certificate") or {}).get("sha256"))
    v["integrity"] = _verify_chain(env)
    return v


def _needs_share(env: dict, r: dict) -> bool:
    """A ready link the owner must act on: not yet shared by hand, or (envelopes that email) not on its way by
    email — the email failed, the link was re-issued without emailing it, or this server can't email now."""
    if not _mail_on(env):
        return r.get("status") == "sent"
    if r.get("status") not in ("sent", "viewed") or r.get("notified_at"):
        return False
    return r.get("email_state") != "queued" or bool(r.get("email_held")) or not mail_available()


def _next_action(env: dict) -> Optional[str]:
    st = env.get("status")
    rs = env.get("recipients") or []
    if st == "draft":
        return "Draft — finish setup"
    if st == "completed":
        return "Completed — download"
    if st == "voided":
        return "Voided"
    if st == "expired":
        return "Expired"
    if st == "declined":
        who = _recip(env, (env.get("decline") or {}).get("recipient_id") or "")
        return f"Declined by {who['name']}" if who else "Declined"
    share = [r["name"] for r in rs if _needs_share(env, r)]
    failed = [r["name"] for r in rs if _needs_share(env, r) and r.get("email_state") == "failed"]
    if failed and _mail_on(env):
        return "Couldn't email " + ", ".join(failed[:2]) + (f" +{len(failed) - 2}" if len(failed) > 2 else "") + \
            " — share the link"
    if share:
        return "Share link with " + ", ".join(share[:2]) + (f" +{len(share) - 2}" if len(share) > 2 else "")
    mailing = [r["name"] for r in rs if r.get("email_state") == "queued" and r.get("status") == "sent"
               and mail_available()]
    if mailing:
        return "Emailing " + ", ".join(mailing[:2]) + (f" +{len(mailing) - 2}" if len(mailing) > 2 else "")
    wait = [r["name"] for r in rs if r.get("role") in ACTORS and r.get("status") in ("notified", "viewed")]
    if wait:
        return "Waiting for " + ", ".join(wait[:2]) + (f" +{len(wait) - 2}" if len(wait) > 2 else "")
    return "In progress"


def _summary(env: dict) -> dict:
    rs = env.get("recipients") or []
    actors = [r for r in rs if r.get("role") in ACTORS]
    return {"id": env["id"], "title": env.get("title"), "status": env.get("status"),
            "created_at": env.get("created_at"), "updated_at": env.get("updated_at"),
            "sent_at": env.get("sent_at"), "completed_at": env.get("completed_at"),
            "expires_at": env.get("expires_at"), "documents": len(env.get("documents") or []),
            "recipients": [dict({k: r.get(k) for k in ("id", "name", "email", "role", "routing_order", "status",
                                                       "email_state", "link_emailed_at", "email_held")},
                                **({"email_state": None} if r.get("email_state") == "queued" and not mail_available()
                                   else {}))
                           for r in sorted(rs, key=lambda r: (r.get("routing_order") or 1))],
            "mail": {"on": True} if _mail_on(env) else None,
            "next_action": _next_action(env),
            "signed": sum(1 for r in actors if r.get("status") == "signed"), "signers": len(actors)}


def _require_draft(env: dict):
    if env.get("status") != "draft":
        raise HTTPException(status_code=409, detail="This envelope has been sent — it can no longer be edited.")


def _get_env_or_404(eid: str, caller: str) -> dict:
    env = _load(eid, caller)
    if not env:
        raise HTTPException(status_code=404, detail="envelope not found")
    return env


# ------------------------------------------------------------------------------------------------- routing
def _activate(env: dict, order: int, meta: Optional[dict]) -> None:
    t = _now()
    for r in env.get("recipients") or []:
        if r.get("status") not in ("created", "pending"):
            continue
        ro = int(r.get("routing_order") or 1)
        if (r.get("role") in ACTORS and ro == order) or (r.get("role") == "cc" and ro <= order):
            r["status"] = "notified" if r.get("notified_at") else "sent"
            r["sent_at"] = t
            _event(env, "link_generated", "system", meta, r["id"], {"routing_order": ro, "note": r.get("name")})
            _queue_mail(env, "invite", r["id"])


def _advance(env: dict, meta: Optional[dict]) -> None:
    actors = [r for r in env.get("recipients") or [] if r.get("role") in ACTORS]
    cur = env.get("current_order")
    group = [r for r in actors if int(r.get("routing_order") or 1) == cur]
    if group and not all(r.get("status") == "signed" for r in group):
        return
    remaining = sorted({int(r.get("routing_order") or 1) for r in actors if r.get("status") != "signed"})
    if remaining:
        env["current_order"] = remaining[0]
        _event(env, "routing_advanced", "system", meta, None, {"routing_order": remaining[0]})
        _activate(env, remaining[0], meta)
    else:
        _complete(env, meta)


def _complete(env: dict, meta: Optional[dict]) -> None:
    t = _now()
    env["status"], env["completed_at"], env["current_order"] = "completed", t, None
    for r in env.get("recipients") or []:
        if r.get("role") == "cc":
            r["status"], r["completed_at"] = "completed", t
            if not r.get("sent_at"):
                r["sent_at"] = t
    _event(env, "completed", "system", meta)
    owner = env["owner"]
    docs = sorted(env.get("documents") or [], key=lambda d: d.get("order", 0))
    parts = [_get_blob(owner, d.get("working_blob_id") or d["blob_id"]) for d in docs]
    cert = _certificate(env)
    combined = P.combine(parts + [cert])
    final, seal = SEAL.seal_pdf(combined)
    if not seal.get("sealed") and (env.get("_seal_plan") or {}).get("configured"):
        # the certificate page announced a seal that didn't happen: rebuild it so the stored PDF never claims one
        cert = _certificate(env, seal_failed=True)
        final = P.combine(parts + [cert])
    env.pop("_seal_plan", None)
    bid = _put_blob(owner, env["id"], "final", final, "application/pdf")
    env["final"] = {"blob_id": bid, "sha256": P.sha256(final), "size": len(final), "pages": P.page_count(final),
                    "cert_pages": P.page_count(cert), "seal": _seal_record(seal)}
    if seal.get("sealed"):                         # the standalone certificate, sealed once here (not per download)
        excerpt, xs = SEAL.seal_pdf(cert, reason=f"Sealed by {brand.name()}: Certificate of Completion")
        if xs.get("sealed"):
            xb = _put_blob(owner, env["id"], "certificate", excerpt, "application/pdf")
            env["final"]["certificate"] = {"blob_id": xb, "sha256": P.sha256(excerpt)}
    detail = {"sha256": env["final"]["sha256"], "note": "final PDF hash recorded"}
    if seal.get("sealed"):
        detail.update({"note": f"final PDF sealed ({seal.get('level')}) and its hash recorded",
                       "seal_cert_sha256": (seal.get("cert") or {}).get("sha256"), "tsa": seal.get("tsa")})
    else:
        detail["seal"] = f"not sealed: {seal.get('reason')}"
    _event(env, "sealed", "system", meta, None, detail)
    for r in env.get("recipients") or []:
        _queue_mail(env, "completed", r["id"])
    _queue_mail(env, "owner_completed")


def _seal_record(seal: dict) -> dict:
    """What the envelope keeps about its seal (no key material; the certificate by fingerprint)."""
    if not seal.get("sealed"):
        return {"sealed": False, "reason": seal.get("reason")}
    c = seal.get("cert") or {}
    return {"sealed": True, "level": seal.get("level"), "tsa": seal.get("tsa"), "sealed_at": seal.get("sealed_at"),
            "cert_subject": c.get("subject"), "cert_sha256": c.get("sha256"), "cert_serial": c.get("serial"),
            "tsa_errors": (seal.get("tsa_errors") or [])[:3] or None}


def _certificate(env: dict, seal_failed: bool = False) -> bytes:
    owner = env["owner"]
    sigs = {}
    for r in env.get("recipients") or []:
        if r.get("sig_blob_id"):
            try:
                sigs[r["id"]] = _get_blob(owner, r["sig_blob_id"])
            except Exception:
                pass
    view = copy.deepcopy(env)
    for r in view.get("recipients") or []:
        r["access_code_set"] = bool(r.get("ac_hash"))
    view["integrity"] = _verify_chain(env)
    plan = None
    if env.get("status") == "completed":
        plan = {"configured": False} if seal_failed else SEAL.status()
        if not env.get("final"):
            env["_seal_plan"] = plan               # what this certificate claims, checked against the outcome
    view["seal_plan"] = plan
    return P.certificate(view, sigs)


# ------------------------------------------------------------------------------------------------- owner API
class EnvCreate(BaseModel):
    title: Optional[str] = Field("Untitled envelope", max_length=200)
    message: Optional[str] = Field(None, max_length=2000)
    signing_order: Optional[str] = Field(None, max_length=20)
    sender_name: Optional[str] = Field(None, max_length=120)
    sender_email: Optional[str] = Field(None, max_length=254)
    expires_at: Optional[str] = Field(None, max_length=40)


class EnvPatch(BaseModel):
    title: Optional[str] = Field(None, max_length=200)
    message: Optional[str] = Field(None, max_length=2000)
    signing_order: Optional[str] = Field(None, max_length=20)
    sender_name: Optional[str] = Field(None, max_length=120)
    sender_email: Optional[str] = Field(None, max_length=254)
    expires_at: Optional[str] = Field(None, max_length=40)


class NotifyIn(BaseModel):
    notify: Optional[bool] = None                   # /send: email the links (default no); regenerate: email the new
                                                    # link when the envelope emails its links (default yes)


class RecipIn(BaseModel):
    id: Optional[str] = Field(None, max_length=40)
    name: str = Field(..., max_length=200)
    email: str = Field(..., max_length=254)
    role: str = Field("signer", max_length=20)
    routing_order: int = Field(1, ge=1, le=99)
    note: Optional[str] = Field(None, max_length=1000)
    access_code: Optional[str] = Field(None, max_length=64)
    email_code: Optional[bool] = None


class RecipsPut(BaseModel):
    recipients: List[RecipIn] = Field(default_factory=list)


class RecipPatch(BaseModel):
    name: Optional[str] = Field(None, max_length=200)
    email: Optional[str] = Field(None, max_length=254)
    note: Optional[str] = Field(None, max_length=1000)
    access_code: Optional[str] = Field(None, max_length=64)
    email_code: Optional[bool] = None
    notify: Optional[bool] = None                   # email the new link when one is issued (default: yes)


class FieldIn(BaseModel):
    id: Optional[str] = Field(None, max_length=40)
    recipient_id: str = Field(..., max_length=40)
    document_id: str = Field(..., max_length=40)
    page: int = Field(..., ge=1, le=MAX_PAGES)
    x: float
    y: float
    w: float
    h: float
    type: str = Field(..., max_length=20)
    required: Optional[bool] = None
    label: Optional[str] = Field(None, max_length=80)


class FieldsPut(BaseModel):
    fields: List[FieldIn] = Field(default_factory=list)


class OrderPut(BaseModel):
    order: List[str] = Field(default_factory=list)


class VoidIn(BaseModel):
    reason: Optional[str] = Field(None, max_length=500)


def _apply_sender_email(env: dict, val) -> None:
    """The sender's own address: Reply-To on the emails recipients get, and where notes about the envelope go."""
    if val is None:
        return
    em = _clean(val, 254).lower()
    if em and not (_EMAIL.match(em) and _mailable(em)):
        raise HTTPException(status_code=422, detail="Your email address doesn't look right.")
    env["sender_email"] = em


def _apply_expiry(env: dict, val) -> None:
    if val is None:
        return
    if val == "":
        env["expires_at"] = None
        return
    d = _parse_iso(val)
    if not d:
        raise HTTPException(status_code=422, detail="Expiry must be an ISO date/time.")
    env["expires_at"] = _iso(d)


@router.get("/v1/esign/envelopes")
def list_envelopes(request: Request, status: str = "all", caller: str = Depends(_caller)):
    rows = _repo().list_documents(caller, pipeline=PIPE_ENV, limit=10000) or []
    out = []
    for row in rows:
        env = row.get("review")
        if not isinstance(env, dict) or env.get("owner") != caller or not env.get("id"):
            continue
        env = _expire_and_save(copy.deepcopy(env))
        st = env.get("status")
        needs_share = st == "sent" and any(_needs_share(env, r) for r in env.get("recipients") or [])
        keep = (status in ("", "all")
                or (status == "action" and needs_share)
                or (status == "waiting" and st == "sent" and not needs_share)
                or status == st)
        if keep:
            out.append(_summary(env))
    out.sort(key=lambda s: s.get("updated_at") or "", reverse=True)
    return {"envelopes": out}


@router.post("/v1/esign/envelopes")
def create_envelope(body: EnvCreate, request: Request, caller: str = Depends(_writer)):
    env = _blank_env(caller, _clean(body.title, 200) or "Untitled envelope")
    env["message"] = _clean(body.message, 2000)
    env["signing_order"] = "parallel" if body.signing_order == "parallel" else "sequential"
    prof = _profile(caller)                 # default the sender to the signed-in person, not the product name
    env["sender_name"] = _clean(body.sender_name, 120) or _clean(prof.get("name"), 120)
    if body.sender_email is not None:
        _apply_sender_email(env, body.sender_email)
    elif prof.get("email"):
        try:                                # the account email is a default only: never block creating the envelope
            _apply_sender_email(env, prof["email"])
        except HTTPException:
            pass
    _apply_expiry(env, body.expires_at)
    eid = _repo().store_document(b"", "application/json", caller, "esign", copy.deepcopy(env), owner=caller)
    if not eid:
        raise HTTPException(status_code=500, detail="Could not create the envelope.")
    env["id"] = eid
    _event(env, "created", caller, _meta(request))
    try:
        _save(env)
    except Exception:
        _repo().delete_document(eid, caller)
        raise
    _owner_log(request, "esign_create", caller, {"title": env["title"]}, {"envelope_id": eid})
    return _owner_view(env)


@router.get("/v1/esign/envelopes/{eid}")
def get_envelope(eid: str, request: Request, caller: str = Depends(_caller)):
    env = _expire_and_save(_get_env_or_404(eid, caller))
    return _owner_view(env)


@router.patch("/v1/esign/envelopes/{eid}")
def patch_envelope(eid: str, body: EnvPatch, request: Request, caller: str = Depends(_writer)):
    with _lock(eid):
        env = _get_env_or_404(eid, caller)
        st = env.get("status")
        if st == "draft":
            if body.title is not None:
                env["title"] = _clean(body.title, 200) or "Untitled envelope"
            if body.signing_order is not None:
                env["signing_order"] = "parallel" if body.signing_order == "parallel" else "sequential"
            if body.sender_name is not None:
                env["sender_name"] = _clean(body.sender_name, 120)
        elif st != "sent":
            raise HTTPException(status_code=409, detail="This envelope can no longer be changed.")
        if body.message is not None:
            env["message"] = _clean(body.message, 2000)
        _apply_sender_email(env, body.sender_email)
        if "expires_at" in body.model_fields_set:          # explicit null = remove the expiry
            _apply_expiry(env, body.expires_at if body.expires_at is not None else "")
        last = (env.get("events") or [{}])[-1]
        if not (last.get("event") == "updated" and st == "draft"):
            _event(env, "updated", caller, _meta(request))
        _save(env)
        return _owner_view(env)


@router.delete("/v1/esign/envelopes/{eid}")
def delete_envelope(eid: str, request: Request, caller: str = Depends(_writer)):
    with _lock(eid):
        env = _get_env_or_404(eid, caller)
        if env.get("status") != "draft":
            raise HTTPException(status_code=409, detail="Only drafts can be deleted — envelopes that were sent are "
                                                        "kept as signing records (void an in-progress one instead).")
        for d in env.get("documents") or []:
            for k in ("blob_id", "original_blob_id", "working_blob_id"):
                _del_blob(caller, d.get(k))
        for r in env.get("recipients") or []:
            _del_blob(caller, r.get("sig_blob_id"))
            _del_blob(caller, r.get("initials_blob_id"))
        _repo().delete_document(eid, caller)
    _owner_log(request, "esign_delete", caller, {"envelope_id": eid}, {"ok": True})
    return {"ok": True}


@router.post("/v1/esign/envelopes/{eid}/documents")
def add_document(eid: str, request: Request, file: UploadFile = File(...), caller: str = Depends(_writer)):
    if not _rate_ok(f"upload:{caller}", 30):          # uploads may convert (seconds each): 30 per minute per owner
        raise HTTPException(status_code=429, detail="Too many uploads — please wait a minute.")
    env = _get_env_or_404(eid, caller)
    _require_draft(env)
    if len(env.get("documents") or []) >= MAX_DOCS:
        raise HTTPException(status_code=409, detail=f"An envelope can hold up to {MAX_DOCS} documents.")
    raw = file.file.read(P.MAX_FILE_BYTES + 1)
    if len(raw) > P.MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="Files must be 25 MB or smaller.")
    pages_left = MAX_PAGES - sum(int(d.get("page_count") or 0) for d in env.get("documents") or [])
    if pages_left <= 0:
        raise HTTPException(status_code=409, detail=f"An envelope can hold up to {MAX_PAGES} pages in total.")
    try:
        # Word / ODT / RTF are converted to PDF here (headless LibreOffice, can take seconds): the ORIGINAL blob keeps
        # the bytes exactly as uploaded (with their real type, so the owner can download the .docx); the NORMALIZED
        # blob is the converted PDF that every page render, field and signature works on.
        norm = P.normalize_upload(raw, file.filename or "", file.content_type, max_pages=pages_left)
    except P.PdfError as e:
        raise HTTPException(status_code=422, detail=str(e))
    ctype_orig = norm.get("source_type") or (
        "image/png" if P._is_png(raw) else "image/jpeg" if P._is_jpeg(raw) else "application/pdf")
    src_fmt = norm.get("source_format") or ""
    converted = src_fmt in P.OFFICE_FORMATS
    name = _clean(os.path.basename(file.filename or "Document"), 200) or "Document"
    orig_bid = _put_blob(caller, eid, "original", raw, ctype_orig)
    norm_bid = _put_blob(caller, eid, "normalized", norm["pdf"], "application/pdf")
    with _lock(eid):
        env = _get_env_or_404(eid, caller)
        docs = env.get("documents") or []
        problem = None
        if env.get("status") != "draft":
            problem = (409, "This envelope has been sent — it can no longer be edited.")
        elif len(docs) >= MAX_DOCS:
            problem = (409, f"An envelope can hold up to {MAX_DOCS} documents.")
        elif sum(int(d.get("page_count") or 0) for d in docs) + len(norm["pages"]) > MAX_PAGES:
            problem = (409, f"An envelope can hold up to {MAX_PAGES} pages in total.")
        elif sum(int(d.get("stored_size") or d.get("size") or 0) for d in docs) + max(len(raw), len(norm["pdf"])) \
                > MAX_ENVELOPE_BYTES:
            problem = (413, "This envelope is too large (60 MB total).")
        if problem:
            _del_blob(caller, orig_bid)
            _del_blob(caller, norm_bid)
            raise HTTPException(status_code=problem[0], detail=problem[1])
        doc = {"id": "doc_" + _hex(5), "name": name, "order": len(docs), "pages": norm["pages"],
               "page_count": len(norm["pages"]), "size": len(raw), "stored_size": max(len(raw), len(norm["pdf"])),
               "sha256_original": P.sha256(raw),
               "kind": norm["kind"], "content_type_original": ctype_orig,
               "blob_id": norm_bid, "original_blob_id": orig_bid, "working_blob_id": None}
        if converted:
            doc["source_format"] = src_fmt
            doc["sha256_converted"] = P.sha256(norm["pdf"])
        docs.append(doc)
        env["documents"] = docs
        note = f"{name} ({doc['page_count']} page(s)" + (f", converted to PDF from {src_fmt.upper()})" if converted else ")")
        detail = {"note": note, "sha256": doc["sha256_original"]}
        if converted:                             # chain the hash of the PDF the signers will see, not only the .docx
            detail["sha256_converted"] = doc["sha256_converted"]
        _event(env, "document_added", caller, _meta(request), None, detail)
        _save(env)
        out = {k: v for k, v in doc.items() if not k.endswith("blob_id")}
        return out


@router.delete("/v1/esign/envelopes/{eid}/documents/{did}")
def remove_document(eid: str, did: str, request: Request, caller: str = Depends(_writer)):
    with _lock(eid):
        env = _get_env_or_404(eid, caller)
        _require_draft(env)
        d = _doc(env, did)
        if not d:
            raise HTTPException(status_code=404, detail="document not found")
        env["documents"] = [x for x in env["documents"] if x["id"] != did]
        for i, x in enumerate(sorted(env["documents"], key=lambda x: x.get("order", 0))):
            x["order"] = i
        env["fields"] = [f for f in env.get("fields") or [] if f.get("document_id") != did]
        _event(env, "document_removed", caller, _meta(request), None, {"note": d.get("name")})
        _save(env)
    for k in ("blob_id", "original_blob_id", "working_blob_id"):
        _del_blob(caller, d.get(k))
    return {"ok": True}


@router.put("/v1/esign/envelopes/{eid}/documents/order")
def order_documents(eid: str, body: OrderPut, request: Request, caller: str = Depends(_writer)):
    with _lock(eid):
        env = _get_env_or_404(eid, caller)
        _require_draft(env)
        ids = [d["id"] for d in env.get("documents") or []]
        if sorted(ids) != sorted(body.order) or len(set(body.order)) != len(body.order):
            raise HTTPException(status_code=422, detail="order must list every document exactly once")
        pos = {did: i for i, did in enumerate(body.order)}
        for d in env["documents"]:
            d["order"] = pos[d["id"]]
        env["documents"].sort(key=lambda d: d["order"])
        _save(env)
        return _owner_view(env)


def _png_response(request: Request, png_fn, etag: str, public: bool) -> Response:
    headers = dict(_PUB_HEADERS) if public else {}
    headers["Cache-Control"] = "private, no-cache"
    headers["ETag"] = etag
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers=headers)
    try:
        png = png_fn()
    except P.PdfError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return Response(content=png, media_type="image/png", headers=headers)


@router.get("/v1/esign/envelopes/{eid}/documents/{did}/pages/{n}.png")
def owner_page_png(eid: str, did: str, n: int, request: Request, scale: float = 1.5,
                   caller: str = Depends(_img_caller)):
    env = _get_env_or_404(eid, caller)
    d = _doc(env, did)
    if not d or n < 1 or n > int(d.get("page_count") or 0):
        raise HTTPException(status_code=404, detail="page not found")
    bid = (d.get("working_blob_id") if env.get("status") != "draft" else None) or d["blob_id"]
    sc = _quant_scale(scale)
    return _png_response(request, lambda: _page_png(caller, bid, n - 1, sc), f'"{bid}-{n}-{sc}"', public=False)


def _safe_filename(s: str, ext: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._ -]+", "", s or "").strip() or "document"
    base = base[:80]
    return base if base.lower().endswith(ext) else base + ext


def _attachment(data: bytes, ctype: str, filename: str) -> Response:
    return Response(content=data, media_type=ctype,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"})


@router.get("/v1/esign/envelopes/{eid}/documents/{did}/file")
def owner_document_file(eid: str, did: str, request: Request, which: str = "original",
                        caller: str = Depends(_caller)):
    env = _get_env_or_404(eid, caller)
    d = _doc(env, did)
    if not d:
        raise HTTPException(status_code=404, detail="document not found")
    if which == "current":
        data = _get_blob(caller, d.get("working_blob_id") or d["blob_id"])
        return _attachment(data, "application/pdf", _safe_filename(os.path.splitext(d["name"])[0] + " (current)", ".pdf"))
    data = _get_blob(caller, d["original_blob_id"])
    ct = d.get("content_type_original") or "application/pdf"
    base, name_ext = os.path.splitext(d["name"])
    fmt = d.get("source_format")
    if fmt in P.OFFICE_FORMATS:
        # the file exactly as uploaded: keep the user's own Word-family extension (.doc holding RTF, .docm …)
        ext = name_ext.lower() if name_ext.lower() in P.OFFICE_EXTS else P.OFFICE_FORMATS[fmt]["ext"]
    else:
        ext = {"image/png": ".png", "image/jpeg": ".jpg"}.get(ct) or \
            {v["mime"]: v["ext"] for v in P.OFFICE_FORMATS.values()}.get(ct, ".pdf")
    return _attachment(data, ct, _safe_filename(base, ext))


def _reset_access_counters(r: dict) -> None:
    for k in ("ac_fail", "ac_lock_until", "ac_total_fail", "ac_locked", "ac_last_ok_at"):
        r.pop(k, None)


def _reset_email_code(r: dict) -> None:
    for k in ("ec_hash", "ec_salt", "ec_expires", "ec_fail", "ec_lock_until", "ec_grant", "ec_sends", "ec_last_sent",
              "ec_verified_at", "ec_total_fail", "ec_locked"):
        r.pop(k, None)


def _set_email_code(r: dict, on) -> None:
    if on is None:
        return
    if on and not smtp_configured():
        raise HTTPException(status_code=422, detail="Email codes need an outgoing mail server, and none is set up "
                                                    "on this server (ESIGN_SMTP_HOST). Use an access code instead.")
    if bool(on) != bool(r.get("ec_required")):
        _reset_email_code(r)
    r["ec_required"] = bool(on)


def _set_access_code(r: dict, code) -> None:
    if code is None:
        return
    code = str(code).strip()
    if code == "":
        for k in ("ac_hash", "ac_salt"):
            r.pop(k, None)
        _reset_access_counters(r)
        return
    if len(code) < 4:
        raise HTTPException(status_code=422, detail="Access codes must be at least 4 characters.")
    r["ac_salt"] = _hex(8)
    r["ac_hash"] = _ac_hash(r["ac_salt"], code)
    _reset_access_counters(r)


@router.put("/v1/esign/envelopes/{eid}/recipients")
def put_recipients(eid: str, body: RecipsPut, request: Request, caller: str = Depends(_writer)):
    if len(body.recipients) > MAX_RECIPIENTS:
        raise HTTPException(status_code=422, detail=f"Up to {MAX_RECIPIENTS} recipients per envelope.")
    with _lock(eid):
        env = _get_env_or_404(eid, caller)
        _require_draft(env)
        existing = {r["id"]: r for r in env.get("recipients") or []}
        seen_ids = set()
        used_colors = set()
        out, problems = [], []
        for i, ri in enumerate(body.recipients):
            name, email = _clean(ri.name, 120), _clean(ri.email, 200).lower()
            if not name:
                problems.append(f"Recipient {i + 1}: name is required")
            if not _EMAIL.match(email):
                problems.append(f"Recipient {i + 1}: '{email or '(blank)'}' is not a valid email address")
            if ri.role not in ROLES:
                problems.append(f"Recipient {i + 1}: unknown role")
            reuse = ri.id and ri.id in existing and ri.id not in seen_ids
            r = copy.deepcopy(existing[ri.id]) if reuse else {"id": "rcp_" + _hex(5)}
            seen_ids.add(r["id"])
            r.update({"name": name, "email": email, "role": ri.role, "routing_order": int(ri.routing_order),
                      "note": _clean(ri.note, 1000) or None})
            r.setdefault("status", "created")
            r.setdefault("link_version", 1)
            r.setdefault("view_count", 0)
            for k in ("sent_at", "notified_at", "first_viewed_at", "last_viewed_at", "signed_at", "declined_at",
                      "completed_at", "decline_reason", "sign_ip", "sign_ua", "consented_at"):
                r.setdefault(k, None)
            _set_access_code(r, ri.access_code)
            _set_email_code(r, ri.email_code)
            out.append(r)
        if problems:
            raise HTTPException(status_code=422, detail="; ".join(problems[:6]))
        for r in out:                                 # keep existing colours, then hand out free ones
            if "color" in r and r["color"] not in used_colors:
                used_colors.add(r["color"])
            else:
                r.pop("color", None)
        for r in out:
            if "color" not in r:
                free = [c for c in range(8) if c not in used_colors]
                r["color"] = free[0] if free else len(used_colors) % 8
                used_colors.add(r["color"])
        # routing_order per recipient is authoritative; the envelope flag is derived for display/certificate
        orders = {r["routing_order"] for r in out if r["role"] in ACTORS}
        env["signing_order"] = "parallel" if len(orders) <= 1 else "sequential"
        signers = {r["id"] for r in out if r["role"] == "signer"}
        env["fields"] = [f for f in env.get("fields") or [] if f.get("recipient_id") in signers]
        env["recipients"] = out
        last = (env.get("events") or [{}])[-1]
        if last.get("event") != "recipients_updated":
            _event(env, "recipients_updated", caller, _meta(request), None, {"note": f"{len(out)} recipient(s)"})
        _save(env)
        return _owner_view(env)


@router.put("/v1/esign/envelopes/{eid}/fields")
def put_fields(eid: str, body: FieldsPut, request: Request, caller: str = Depends(_writer)):
    if len(body.fields) > MAX_FIELDS:
        raise HTTPException(status_code=422, detail=f"Up to {MAX_FIELDS} fields per envelope.")
    with _lock(eid):
        env = _get_env_or_404(eid, caller)
        _require_draft(env)
        rmap = {r["id"]: r for r in env.get("recipients") or []}
        dmap = {d["id"]: d for d in env.get("documents") or []}
        out, seen = [], set()
        eps = 1e-4
        for i, fi in enumerate(body.fields):
            r, d = rmap.get(fi.recipient_id), dmap.get(fi.document_id)
            if not r or r.get("role") != "signer":
                raise HTTPException(status_code=422, detail=f"Field {i + 1}: assign it to a recipient who needs to sign")
            if not d:
                raise HTTPException(status_code=422, detail=f"Field {i + 1}: unknown document")
            if fi.page > int(d.get("page_count") or 0):
                raise HTTPException(status_code=422, detail=f"Field {i + 1}: page {fi.page} does not exist")
            if fi.type not in FIELD_TYPES:
                raise HTTPException(status_code=422, detail=f"Field {i + 1}: unknown type")
            x, y, w, h = float(fi.x), float(fi.y), float(fi.w), float(fi.h)
            if not (-eps <= x <= 1 and -eps <= y <= 1 and 0.003 <= w <= 1 + eps and 0.003 <= h <= 1 + eps):
                raise HTTPException(status_code=422, detail=f"Field {i + 1}: position is outside the page")
            x, y = max(0.0, x), max(0.0, y)
            w, h = min(w, 1.0 - x), min(h, 1.0 - y)
            if w < 0.003 or h < 0.003:
                raise HTTPException(status_code=422, detail=f"Field {i + 1}: position is outside the page")
            fid = fi.id if (fi.id and _FID.match(fi.id) and fi.id not in seen) else "fld_" + _hex(5)
            seen.add(fid)
            req = fi.required if fi.required is not None else (fi.type != "checkbox")
            if fi.type == "date_signed":
                req = True
            out.append({"id": fid, "recipient_id": r["id"], "document_id": d["id"], "page": int(fi.page),
                        "x": round(x, 6), "y": round(y, 6), "w": round(w, 6), "h": round(h, 6), "type": fi.type,
                        "required": bool(req), "label": _clean(fi.label, 80) or None, "value": None})
        env["fields"] = out
        last = (env.get("events") or [{}])[-1]
        recent = last.get("event") == "fields_updated" and _parse_iso(last.get("ts")) and \
            (_now_dt() - _parse_iso(last["ts"])).total_seconds() < 300
        if not recent:
            _event(env, "fields_updated", caller, _meta(request), None, {"note": f"{len(out)} field(s)"})
        _save(env)
        return _owner_view(env)


@router.post("/v1/esign/envelopes/{eid}/send")
def send_envelope(eid: str, request: Request, body: Optional[NotifyIn] = None, caller: str = Depends(_writer)):
    """Send: links for the first routing group. body.notify=true — the server emails each link (when it can email);
    left out or false — the owner shares the links themselves."""
    if _key_is_public_fallback() and (os.environ.get("ESIGN_ENV") or "").strip().lower() == "production":
        raise HTTPException(status_code=503, detail="Signing links are disabled until ESIGN_SECRET is configured on "
                                                    "the server.")
    with _lock(eid):
        env = _get_env_or_404(eid, caller)
        _require_draft(env)
        problems = []
        docs, rs, fs = env.get("documents") or [], env.get("recipients") or [], env.get("fields") or []
        if not docs:
            problems.append("Add at least one document.")
        actors = [r for r in rs if r.get("role") in ACTORS]
        if not actors:
            problems.append("Add at least one recipient who needs to sign or view.")
        for r in rs:
            if r.get("role") == "signer" and not any(f.get("recipient_id") == r["id"] for f in fs):
                problems.append(f"{r.get('name')} needs to sign but has no fields — place at least one field for them.")
            if not _EMAIL.match(r.get("email") or ""):
                problems.append(f"{r.get('name')}: invalid email address.")
        dids = {d["id"] for d in docs}
        rids = {r["id"] for r in rs if r.get("role") == "signer"}
        if any(f.get("document_id") not in dids or f.get("recipient_id") not in rids for f in fs):
            problems.append("Some fields refer to removed documents or recipients — re-open Place fields and save.")
        exp = _parse_iso(env.get("expires_at"))
        if exp and exp <= _now_dt():
            problems.append("The expiry date is in the past.")
        if problems:
            return JSONResponse({"detail": "This envelope isn't ready to send.", "problems": problems}, status_code=422)
        want = bool(body.notify) if body is not None and body.notify is not None else False
        base = _link_base(request, caller)
        can = mail_available() and bool(base)
        if want and can and not _plain(env.get("sender_name"), 120):
            problems.append("Add your name as the sender: recipients see it in the email.")
            return JSONResponse({"detail": "This envelope isn't ready to send.", "problems": problems},
                                status_code=422)
        if want and not can:
            raise HTTPException(status_code=422, detail="This server can't email the links"
                                + (" — no outgoing mail is set up (ESIGN_SMTP_HOST, ESIGN_MAIL=1)"
                                   if not mail_available() else " — ESIGN_PUBLIC_URL is not set")
                                + ". Send it without email and share the links yourself.")
        meta = _meta(request)
        env["signing_order"] = "parallel" if len({int(r.get("routing_order") or 1) for r in actors}) <= 1 else "sequential"
        if can and want:
            env["mail"] = {"on": True, "base": base}
        env["status"], env["sent_at"] = "sent", _now()
        if not env.get("sender_name"):
            env["sender_name"] = _clean(_profile(env["owner"]).get("name"), 120) or brand.name()
        for r in rs:
            r["status"], r["link_version"] = "pending", int(r.get("link_version") or 1)
        env["current_order"] = min(int(r.get("routing_order") or 1) for r in actors)
        _event(env, "sent", caller, meta, None, {"note": f"{len(rs)} recipient(s), {len(docs)} document(s)"
                                                       + ("; the links are emailed" if _mail_on(env) else "")})
        _activate(env, env["current_order"], meta)
        _save(env)
    _owner_log(request, "esign_send", caller, {"envelope_id": eid}, {"status": "sent", "email": _mail_on(env)})
    return _owner_view(_after_mail(env))


def _after_mail(env: dict) -> dict:
    """Owner requests: deliver what the change queued (waiting up to MAIL_WAIT seconds), then the fresh envelope."""
    if not env.get("outbox"):
        return env
    _kick(env, wait=MAIL_WAIT)
    return _load(env["id"], env["owner"]) or env


def _retire_link_email(env: dict, r: dict) -> None:
    """The link was replaced: an unsent email for it is dropped (the caller queues one for the new link if wanted),
    and when (and whether) the OLD link was emailed says nothing about the new one (the events keep the history).
    Envelopes that never emailed are left exactly as they were."""
    if not _mail_on(env) and not env.get("outbox"):
        return
    ob = env.get("outbox") or []
    ob[:] = [j for j in ob if not (j.get("rid") == r["id"] and j.get("kind") in ("invite", "remind")
                                   and not j.get("sending"))]
    for k in ("link_emailed_at", "email_error", "email_failed_at"):
        r.pop(k, None)
    r["email_state"] = "queued" if any(j.get("rid") == r["id"] and j.get("kind") not in _OWNER_KINDS
                                       and not (j.get("kind") in _LINK_KINDS and j.get("sending"))
                                       for j in ob) else None


def _recipient_view(env: dict, rid: str, email_note: Optional[str] = None) -> dict:
    v = _owner_view(env)["recipients"][[x["id"] for x in env["recipients"]].index(rid)]
    if email_note:
        v["email_note"] = email_note              # why a new link wasn't emailed (share it yourself)
    return v


def _relink_email(env: dict, r: dict) -> tuple:
    """Email a re-issued link (envelopes that email their links), within RELINK_DAY a day per recipient.
    (queued, why not) — why is None for envelopes that never email (nothing to explain)."""
    if not _mail_on(env):
        return False, None
    if not mail_available():
        return False, "this server isn't emailing links right now"
    try:
        _mq_take([(f"esm-relink:{env['id']}:{r['id']}", RELINK_DAY,
                   "they've been emailed a new link several times today")])
    except _MailQuota as e:
        return False, str(e)
    if not _queue_mail(env, "invite", r["id"]):
        return False, "the email couldn't be queued"
    return True, None


def _sent_recipient(eid: str, rid: str, caller: str):
    env = _get_env_or_404(eid, caller)
    r = _recip(env, rid)
    if not r:
        raise HTTPException(status_code=404, detail="recipient not found")
    return env, r


@router.post("/v1/esign/envelopes/{eid}/recipients/{rid}/notified")
def mark_notified(eid: str, rid: str, request: Request, caller: str = Depends(_writer)):
    with _lock(eid):
        env, r = _sent_recipient(eid, rid, caller)
        if env.get("status") not in ("sent", "completed"):
            raise HTTPException(status_code=409, detail="This envelope isn't in progress.")
        r["notified_at"] = _now()
        if r.get("status") == "sent":
            r["status"] = "notified"
        _event(env, "notified", caller, _meta(request), rid, {"note": f"link marked as shared with {r.get('name')}"})
        _save(env)
        return _owner_view(env)["recipients"][[x["id"] for x in env["recipients"]].index(rid)]


@router.post("/v1/esign/envelopes/{eid}/recipients/{rid}/regenerate")
def regenerate_link(eid: str, rid: str, request: Request, body: Optional[NotifyIn] = None,
                    caller: str = Depends(_writer)):
    with _lock(eid):
        env, r = _sent_recipient(eid, rid, caller)
        if env.get("status") not in ("sent", "completed"):
            raise HTTPException(status_code=409, detail="This envelope isn't in progress.")
        r["link_version"] = int(r.get("link_version") or 1) + 1
        r["notified_at"] = None
        _reset_access_counters(r)
        req = r.get("ec_required")
        _reset_email_code(r)                       # a lock or send cap someone triggered on the old link goes with it
        r["ec_required"] = req
        if r.get("status") == "notified":
            r["status"] = "sent"
        _retire_link_email(env, r)
        _event(env, "link_regenerated", caller, _meta(request), rid,
               {"note": f"new link for {r.get('name')}; the previous link no longer works"})
        skipped = None
        if env.get("status") == "sent" and r.get("status") in ("sent", "viewed") and \
                (body is None or body.notify is not False):
            _queued, skipped = _relink_email(env, r)   # an envelope that emails its links emails the new one
        _save(env)
    return _recipient_view(_after_mail(env), rid, skipped)


@router.post("/v1/esign/envelopes/{eid}/recipients/{rid}/remind")
def remind_recipient(eid: str, rid: str, request: Request, caller: str = Depends(_writer)):
    """Email a recipient their link again (envelopes that email their links): a reminder, or the first email when
    the earlier one couldn't be sent."""
    with _lock(eid):
        env, r = _sent_recipient(eid, rid, caller)
        if env.get("status") != "sent":
            raise HTTPException(status_code=409, detail="This envelope isn't in progress.")
        if not _mail_on(env):
            raise HTTPException(status_code=409, detail="The links for this envelope aren't emailed — copy the "
                                                        "link and send it yourself.")
        if not mail_available():
            raise HTTPException(status_code=503, detail="Email isn't available on this server right now — copy the "
                                                        "link and send it yourself.")
        if r.get("status") in ("pending", "created"):
            raise HTTPException(status_code=409, detail="It isn't their turn yet — they're emailed when it is.")
        if r.get("role") not in ACTORS or r.get("status") not in ("sent", "notified", "viewed"):
            raise HTTPException(status_code=409, detail="Only someone who still has to sign or review can be "
                                                        "reminded.")
        if (r.get("email_state") == "queued" and not r.get("email_error")) or \
                any(j.get("rid") == rid and j.get("sending") for j in env.get("outbox") or []):
            raise HTTPException(status_code=409, detail="An email to them is already on its way.")
        last = _parse_iso(r.get("emailed_at")) if r.get("link_emailed_at") and r.get("email_state") != "failed" \
            else None
        if last and (_now_dt() - last).total_seconds() < REMIND_GAP:
            raise HTTPException(status_code=429, detail="They were emailed a few minutes ago — please wait a little "
                                                        "before reminding them again.")
        try:
            _mq_take([(f"esm-remind:{eid}:{rid}", REMIND_DAY, "reminders")])
        except _MailQuota:
            raise HTTPException(status_code=429, detail=f"They've already been reminded {REMIND_DAY} times today.")
        _queue_mail(env, "remind" if r.get("link_emailed_at") else "invite", rid)
        _save(env)
    _owner_log(request, "esign_remind", caller, {"envelope_id": eid, "recipient_id": rid}, None)
    return _recipient_view(_after_mail(env), rid)


@router.patch("/v1/esign/envelopes/{eid}/recipients/{rid}")
def correct_recipient(eid: str, rid: str, body: RecipPatch, request: Request, caller: str = Depends(_writer)):
    skipped = None
    with _lock(eid):
        env, r = _sent_recipient(eid, rid, caller)
        if env.get("status") != "sent":
            raise HTTPException(status_code=409, detail="Only recipients of an in-progress envelope can be corrected.")
        if r.get("status") in ("signed", "declined", "completed"):
            raise HTTPException(status_code=409, detail="This recipient has already finished.")
        changed = []
        if body.name is not None:
            nm = _clean(body.name, 120)
            if not nm:
                raise HTTPException(status_code=422, detail="Name is required.")
            r["name"] = nm
            changed.append("name")
        if body.email is not None:
            em = _clean(body.email, 200).lower()
            if not _EMAIL.match(em):
                raise HTTPException(status_code=422, detail="That email address isn't valid.")
            r["email"] = em
            changed.append("email")
        if body.note is not None:
            r["note"] = _clean(body.note, 1000) or None
            changed.append("note")
        if body.access_code is not None:
            _set_access_code(r, body.access_code)
            changed.append("access code")
        if body.email_code is not None and bool(body.email_code) != bool(r.get("ec_required")):
            _set_email_code(r, body.email_code)
            changed.append("email code " + ("required" if body.email_code else "removed"))
        if changed:
            note = "updated " + ", ".join(changed)
            if "name" in changed or "email" in changed:
                # the link was issued to the previous details: retire it, and don't carry that person's views or
                # consent over to whoever receives the new link
                r["link_version"] = int(r.get("link_version") or 1) + 1
                for k in ("notified_at", "first_viewed_at", "last_viewed_at", "consented_at"):
                    r[k] = None
                r["view_count"] = 0
                _reset_access_counters(r)
                req = r.get("ec_required")
                _reset_email_code(r)
                r["ec_required"] = req
                _retire_link_email(env, r)
                if r.get("status") in ("notified", "viewed"):
                    r["status"] = "sent"
                note += " — a new signing link was issued; the previous link no longer works"
                if r.get("status") == "sent" and body.notify is not False and _mail_on(env):
                    queued, skipped = _relink_email(env, r)   # emailed to the corrected address
                    if queued:
                        note += "; the new link is being emailed"
            _event(env, "corrected", caller, _meta(request), rid, {"note": note})
            _save(env)
    return _recipient_view(_after_mail(env), rid, skipped)


@router.post("/v1/esign/envelopes/{eid}/void")
def void_envelope(eid: str, body: VoidIn, request: Request, caller: str = Depends(_writer)):
    with _lock(eid):
        env = _get_env_or_404(eid, caller)
        if env.get("status") != "sent":
            raise HTTPException(status_code=409, detail="Only an in-progress envelope can be voided.")
        reason = _clean(body.reason, 500) or "Voided by sender"
        env["status"], env["voided_at"], env["void_reason"], env["current_order"] = "voided", _now(), reason, None
        _event(env, "voided", caller, _meta(request), None, {"note": reason})
        for rr in env.get("recipients") or []:
            if rr.get("link_emailed_at") and rr.get("status") != "declined":
                _queue_mail(env, "voided", rr["id"])   # everyone we emailed a link hears it's off
        _save(env)
    _owner_log(request, "esign_void", caller, {"envelope_id": eid}, {"reason": reason})
    return _owner_view(_after_mail(env))


@router.post("/v1/esign/envelopes/{eid}/duplicate")
def duplicate_envelope(eid: str, request: Request, caller: str = Depends(_writer)):
    src = _get_env_or_404(eid, caller)
    env = _blank_env(caller, (_clean(src.get("title"), 190) or "Untitled envelope") + " (copy)")
    for k in ("message", "signing_order", "sender_name", "sender_email"):
        env[k] = src.get(k) or env[k]
    new_id = _repo().store_document(b"", "application/json", caller, "esign", copy.deepcopy(env), owner=caller)
    if not new_id:
        raise HTTPException(status_code=500, detail="Could not create the copy.")
    env["id"] = new_id
    dmap, rmap = {}, {}
    for d in sorted(src.get("documents") or [], key=lambda d: d.get("order", 0)):
        nd = {k: v for k, v in d.items()}
        nd["id"] = "doc_" + _hex(5)
        nd["original_blob_id"] = _put_blob(caller, new_id, "original", _get_blob(caller, d["original_blob_id"]),
                                           d.get("content_type_original") or "application/pdf")
        nd["blob_id"] = _put_blob(caller, new_id, "normalized", _get_blob(caller, d["blob_id"]), "application/pdf")
        nd["working_blob_id"] = None
        dmap[d["id"]] = nd["id"]
        env["documents"].append(nd)
    for r in src.get("recipients") or []:
        nr = {"id": "rcp_" + _hex(5), "name": r.get("name"), "email": r.get("email"), "role": r.get("role"),
              "routing_order": r.get("routing_order") or 1, "note": r.get("note"), "color": r.get("color", 0),
              "status": "created", "link_version": 1, "view_count": 0,
              "ec_required": bool(r.get("ec_required")) and smtp_configured()}
        for k in ("sent_at", "notified_at", "first_viewed_at", "last_viewed_at", "signed_at", "declined_at",
                  "completed_at", "decline_reason", "sign_ip", "sign_ua", "consented_at"):
            nr[k] = None
        rmap[r["id"]] = nr["id"]
        env["recipients"].append(nr)
    for f in src.get("fields") or []:
        if f.get("document_id") in dmap and f.get("recipient_id") in rmap:
            nf = dict(f, id="fld_" + _hex(5), document_id=dmap[f["document_id"]],
                      recipient_id=rmap[f["recipient_id"]], value=None)
            env["fields"].append(nf)
    _event(env, "created", caller, _meta(request), None, {"note": f"duplicated from {eid}"})
    try:
        _save(env)
    except Exception:
        for d in env["documents"]:
            _del_blob(caller, d.get("original_blob_id"))
            _del_blob(caller, d.get("blob_id"))
        _repo().delete_document(new_id, caller)
        raise
    return _owner_view(env)


@router.get("/v1/esign/envelopes/{eid}/download")
def owner_download(eid: str, request: Request, kind: str = "combined", caller: str = Depends(_caller)):
    with _lock(eid):
        env = _get_env_or_404(eid, caller)
        if env.get("status") == "draft":
            raise HTTPException(status_code=409, detail="Send the envelope first.")
        title = env.get("title") or "envelope"
        if kind == "certificate":
            if (env.get("final") or {}).get("certificate"):
                data = _get_blob(caller, env["final"]["certificate"]["blob_id"])
            elif env.get("final"):
                from pypdf import PdfReader, PdfWriter
                import io
                rd = PdfReader(io.BytesIO(_get_blob(caller, env["final"]["blob_id"])))
                w = PdfWriter()
                for p in rd.pages[-int(env["final"].get("cert_pages") or 1):]:
                    w.add_page(p)
                buf = io.BytesIO()
                w.write(buf)
                data = buf.getvalue()             # an envelope completed before sealing existed: as it was
            else:
                data = _certificate(env)
            fname = _safe_filename(title + " - certificate", ".pdf")
        else:
            if env.get("final"):
                data = _get_blob(caller, env["final"]["blob_id"])
                fname = _safe_filename(title + " - signed", ".pdf")
            else:
                docs = sorted(env.get("documents") or [], key=lambda d: d.get("order", 0))
                data = P.combine([_get_blob(caller, d.get("working_blob_id") or d["blob_id"]) for d in docs]
                                 + [_certificate(env)])
                fname = _safe_filename(title + " - in progress", ".pdf")
        _event(env, "downloaded", caller, _meta(request), None, {"note": "certificate" if kind == "certificate" else "documents"})
        _save(env)
    return _attachment(data, "application/pdf", fname)


VERIFY_SEAL_MAX = MAX_ENVELOPE_BYTES              # files above this are hash-checked only


def verify_max_bytes() -> int:
    """The biggest file the Verify page accepts (signed-in users only; ESIGN_VERIFY_MAX_MB, default 500). The app's
    body-limit middleware enforces the same figure before the upload is read."""
    try:
        mb = int(os.environ.get("ESIGN_VERIFY_MAX_MB") or 500)
    except ValueError:
        mb = 500
    return max(1, mb) * 1024 * 1024


@router.post("/v1/esign/verify")
def verify_document(request: Request, file: UploadFile = File(...), caller: str = Depends(_caller)):
    hh, total, first = hashlib.sha256(), 0, b""
    while True:
        chunk = file.file.read(1024 * 1024)
        if not chunk:
            break
        if not first:
            first = chunk[:5]
        total += len(chunk)
        if total > verify_max_bytes():
            raise HTTPException(status_code=413, detail="That file is too large to verify.")
        hh.update(chunk)
    h = hh.hexdigest()
    seal = None
    if total <= VERIFY_SEAL_MAX and first == b"%PDF-" and _rate_ok(f"esign-verify-seal:{_ipk(request)}", 20):
        file.file.seek(0)
        data = file.file.read()                   # one copy, only for files an envelope could hold
        v = SEAL.validate(data)
        if v.get("signatures"):
            seal = SEAL.summarize(v)
            seal["signatures"] = v["signatures"]
    for row in _repo().list_documents(caller, pipeline=PIPE_ENV, limit=10000) or []:
        env = row.get("review") or {}
        if env.get("owner") != caller:
            continue
        if (env.get("final") or {}).get("sha256") == h:
            return {"match": True, "kind": "final", "envelope_id": env.get("id"), "title": env.get("title"),
                    "completed_at": env.get("completed_at"), "sha256": h, "seal": seal}
        if ((env.get("final") or {}).get("certificate") or {}).get("sha256") == h:
            return {"match": True, "kind": "certificate", "envelope_id": env.get("id"), "title": env.get("title"),
                    "completed_at": env.get("completed_at"), "sha256": h, "seal": seal}
        for d in env.get("documents") or []:
            if d.get("sha256_original") == h:
                return {"match": True, "kind": "original", "envelope_id": env.get("id"), "title": env.get("title"),
                        "document": d.get("name"), "sha256": h, "seal": seal}
    return {"match": False, "sha256": h, "seal": seal}


@router.get("/v1/sign/root.crt")
def esign_root_certificate(request: Request):
    """This server's E-Sign Root CA certificate (public): import it as a trusted root in a PDF reader to see the
    document seal as trusted."""
    _rate(request, "esign-root", 30)
    data = SEAL.root_pem()
    if not data:
        raise HTTPException(status_code=404, detail="No E-Sign root certificate is configured.",
                            headers=_PUB_HEADERS)
    resp = Response(content=data, media_type="application/x-pem-file")
    resp.headers.update({k: v for k, v in _PUB_HEADERS.items() if k != "Cache-Control"})
    fname = re.sub(r"[^A-Za-z0-9]+", "-", brand.legal_name()).strip("-") or "E-Sign"
    resp.headers["Content-Disposition"] = f'attachment; filename="{fname}-E-Sign-Root-CA.crt"'
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp


# ------------------------------------------------------------------------------------------------- public signer API
def _resolve(token: str):
    p = _parse_token(token)
    if not p:
        return None, None
    eid, rid, v = p
    env = _load(eid, None)
    if not env or env.get("status") == "draft":
        return None, None
    r = _recip(env, rid)
    if not r or int(r.get("link_version") or 1) != v:
        return None, None
    return env, r


def _state(env: dict, r: dict, granted: bool, gate: Optional[str] = None) -> str:
    st = env.get("status")
    exp = _parse_iso(env.get("expires_at"))
    if st == "sent" and exp and _now_dt() > exp:
        st = "expired"
    if st in ("voided", "declined", "expired"):
        return st
    if not granted:
        g = gate or ("access_code" if r.get("ac_hash") else "email_code" if r.get("ec_required") else None)
        if g:
            return g
    if st == "completed":
        return "completed"
    if r.get("role") in ACTORS and r.get("status") == "signed":
        return "done"
    if r.get("status") in ("pending", "created"):
        return "waiting"
    return "active"


def _session_view(env: dict, r: dict, granted: bool, gate: Optional[str] = None,
                  meta_browser: Optional[dict] = None) -> dict:
    state = _state(env, r, granted, gate)
    out = {"ok": True, "state": state,
           "envelope": {"title": env.get("title"), "sender_name": env.get("sender_name") or "the sender",
                        "status": env.get("status"), "completed_at": env.get("completed_at"), "message": None,
                        "emails_copy": _copy_mode(env, r)},
           "recipient": {"id": r["id"], "name": r.get("name"), "email": r.get("email"), "role": r.get("role"),
                         "status": r.get("status"), "note": None, "consented": bool(r.get("consented_at")),
                         "signature_level": ("simple" if r.get("status") == "signed" and r.get("role") == "signer"
                                             else None),
                         "signed_at": r.get("signed_at")},
           "documents": [], "fields": [], "progress": {"required": 0, "total": 0},
           "can_download": bool(env.get("status") == "completed" and env.get("final") and granted),
           "sealed": bool((((env.get("final") or {}).get("seal")) or {}).get("sealed")),
           "attempts_left": None, "locked_until": None}
    if r.get("ac_hash") and not granted:
        out["recipient"]["email"] = None
    if r.get("ac_locked"):
        out["locked_until"] = "permanent"
    if state == "access_code":
        out["attempts_left"] = 0 if r.get("ac_locked") else max(0, AC_MAX_FAILS - int(r.get("ac_fail") or 0))
        if not r.get("ac_locked"):
            out["locked_until"] = r.get("ac_lock_until") if _parse_iso(r.get("ac_lock_until")) and \
                _parse_iso(r["ac_lock_until"]) > _now_dt() else None
        return out
    if state == "email_code":
        out["recipient"]["email"] = None
        out["email_masked"] = _mask_email(r.get("email") or "")
        exp = _parse_iso(r.get("ec_expires"))
        out["code_sent"] = bool(r.get("ec_hash") and exp and exp > _now_dt())
        last = _parse_iso(r.get("ec_last_sent"))
        out["resend_in"] = max(0, math.ceil(EC_RESEND_GAP - (_now_dt() - last).total_seconds())) if last else 0
        lock = _parse_iso(r.get("ec_lock_until"))
        out["locked_until"] = r["ec_lock_until"] if lock and lock > _now_dt() else None
        out["attempts_left"] = max(0, AC_MAX_FAILS - int(r.get("ec_fail") or 0)) if out["code_sent"] else None
        out["email_available"] = smtp_configured()
        return out
    if state in ("active", "done", "completed"):
        out["envelope"]["message"] = env.get("message") or None
        out["recipient"]["note"] = r.get("note") or None
        out["documents"] = [{"id": d["id"], "name": d.get("name"), "pages": d.get("pages") or []}
                            for d in sorted(env.get("documents") or [], key=lambda d: d.get("order", 0))]
    if state == "active" and r.get("role") == "signer":
        mine = [dict(f, mine=True) for f in env.get("fields") or [] if f.get("recipient_id") == r["id"]]
        out["fields"] = mine
        out["progress"] = {"required": sum(1 for f in mine if f.get("required")), "total": len(mine)}
        out["signing"] = {"mode": "simple"}
    return out


def _record_view(env: dict, r: dict, meta: dict) -> None:
    t = _now()
    r["view_count"] = int(r.get("view_count") or 0) + 1
    r["last_viewed_at"] = t
    if not r.get("first_viewed_at"):
        r["first_viewed_at"] = t
    if r.get("status") in ("sent", "notified"):
        r["status"] = "viewed"
    last = None
    for e in reversed(env.get("events") or []):
        if e.get("event") == "viewed" and e.get("recipient_id") == r["id"]:
            last = _parse_iso(e.get("ts"))
            break
    if not last or (_now_dt() - last).total_seconds() > VIEW_EVENT_GAP:
        _event(env, "viewed", r.get("email") or r.get("name") or "recipient", meta, r["id"],
               {"note": f"opened by {r.get('name')}"})


def _public_log(env: dict, r: dict, event: str, meta: dict) -> None:
    try:
        _repo().log_activity({"event_type": "esign_" + event, "caller": "signer:" + r["id"], "owner": env["owner"],
                              "ip": meta.get("ip"), "user_agent": meta.get("ua"),
                              "request": {"envelope_id": env["id"], "recipient_id": r["id"]}, "response": None})
    except Exception:
        pass


@router.get("/sign/{token}")
def sign_page(token: str):
    return FileResponse(str(STATIC / "sign.html"), media_type="text/html", headers=_PUB_HEADERS)


@router.get("/v1/sign/{token}/session")
def sign_session(token: str, request: Request):
    _rate(request, "esign-session", 60)
    env, r = _resolve(token)
    if not env:
        return _perr(404, "This signing link is invalid or has been replaced.", {"ok": False, "state": "invalid"})
    meta = _meta(request)
    with _lock(env["id"]):
        env, r = _resolve(token)
        if not env:
            return _perr(404, "This signing link is invalid or has been replaced.", {"ok": False, "state": "invalid"})
        changed = _check_expiry(env)
        gate = _pending_gate(env, r, meta)
        granted = gate is None
        state = _state(env, r, granted, gate)
        if state in ("active", "done", "completed"):
            _record_view(env, r, meta)
            changed = True
        if changed:
            _save(env)
    return JSONResponse(_session_view(env, r, granted, gate, meta), headers=_PUB_HEADERS)


@router.post("/v1/sign/{token}/access")
async def sign_access(token: str, request: Request):
    _rate(request, "esign-access", 10)
    raw = await _read_body(request, 2000)
    if raw is None:
        return _perr(413, "Request too large.")
    try:
        code = str((json.loads(raw or b"{}") or {}).get("code") or "").strip()
    except Exception:
        return _perr(400, "Invalid request.")
    meta = _meta(request)
    return await run_in_threadpool(_access_sync, token, code, meta)


def _access_sync(token: str, code: str, meta: dict):
    env, r = _resolve(token)
    if not env:
        return _perr(404, "This signing link is invalid or has been replaced.", {"state": "invalid"})
    with _lock(env["id"]):
        env, r = _resolve(token)
        if not env:
            return _perr(404, "This signing link is invalid or has been replaced.", {"state": "invalid"})
        if not r.get("ac_hash"):
            return JSONResponse({"ok": True}, headers=_PUB_HEADERS)
        if _state(env, r, True) not in ("active", "waiting", "done", "completed"):
            return _perr(409, "This envelope is no longer available.", {"state": _state(env, r, True)})
        if r.get("ac_locked"):
            return _perr(429, "This link has been locked after too many incorrect codes. Ask the sender for a new "
                              "link.", {"locked_until": "permanent", "attempts_left": 0})
        lock = _parse_iso(r.get("ac_lock_until"))
        if lock and lock > _now_dt():
            return _perr(429, "Too many incorrect attempts. Try again later.", {"locked_until": r["ac_lock_until"],
                                                                                "attempts_left": 0})
        if code and hmac.compare_digest(_ac_hash(r.get("ac_salt") or "", code), r["ac_hash"]):
            r["ac_fail"], r["ac_lock_until"] = 0, None
            last_ok = _parse_iso(r.get("ac_last_ok_at"))
            if not last_ok or (_now_dt() - last_ok).total_seconds() > VIEW_EVENT_GAP:
                r["ac_last_ok_at"] = _now()
                _event(env, "access_code_ok", r.get("email") or "recipient", meta, r["id"])
            _save(env)
            resp = JSONResponse({"ok": True}, headers=_PUB_HEADERS)
            resp.set_cookie(_ac_cookie_name(r), _ac_cookie_value(env["id"], r), max_age=12 * 3600, httponly=True,
                            secure=bool(meta.get("https")), samesite="strict", path="/v1/sign/" + token)
            return resp
        r["ac_fail"] = int(r.get("ac_fail") or 0) + 1
        r["ac_total_fail"] = int(r.get("ac_total_fail") or 0) + 1
        if r["ac_total_fail"] >= AC_HARD_LOCK:
            r["ac_locked"] = True
            _event(env, "access_code_failed", r.get("email") or "recipient", meta, r["id"],
                   {"note": f"link locked after {AC_HARD_LOCK} incorrect codes — the sender must issue a new link"})
            _save(env)
            return _perr(429, "This link has been locked after too many incorrect codes. Ask the sender for a new "
                              "link.", {"locked_until": "permanent", "attempts_left": 0})
        left = max(0, AC_MAX_FAILS - r["ac_fail"])
        extra = {"attempts_left": left}
        if left == 0:
            r["ac_lock_until"] = _iso(_now_dt() + _dt.timedelta(seconds=AC_LOCK_SECS))
            r["ac_fail"] = 0
            extra["locked_until"] = r["ac_lock_until"]
        _event(env, "access_code_failed", r.get("email") or "recipient", meta, r["id"],
               {"note": "locked for 15 minutes" if left == 0 else f"{left} attempt(s) left"})
        _save(env)
        if left == 0:
            return _perr(429, "Too many incorrect attempts. This link is locked for 15 minutes.", extra)
        return _perr(401, "That access code isn't right.", extra)


@router.post("/v1/sign/{token}/email-code")
def sign_email_code_send(token: str, request: Request):
    """Email a fresh 6-digit one-time code to the recipient (only once their access code, if any, is passed)."""
    _rate(request, "esign-ec-send", 6)
    meta = _meta(request)
    env, r = _resolve(token)
    if not env:
        return _perr(404, "This signing link is invalid or has been replaced.", {"state": "invalid"})
    with _lock(env["id"]):
        env, r = _resolve(token)
        if not env:
            return _perr(404, "This signing link is invalid or has been replaced.", {"state": "invalid"})
        gate = _pending_gate(env, r, meta)
        st = _state(env, r, gate is None, gate)
        if st != "email_code":
            return _perr(409, "No email code is needed right now.", {"state": st})
        if not smtp_configured():
            return _perr(503, "Email codes are unavailable right now. Ask the sender for help.", {"state": st})
        now = _now_dt()
        if r.get("ec_locked"):
            return _perr(429, "This link has been locked after too many incorrect codes. Ask the sender for a new "
                              "link.", {"locked_until": "permanent"})
        lock = _parse_iso(r.get("ec_lock_until"))
        if lock and lock > now:
            return _perr(429, "Too many incorrect codes. Try again later.", {"locked_until": r["ec_lock_until"]})
        last = _parse_iso(r.get("ec_last_sent"))
        if last and (now - last).total_seconds() < EC_RESEND_GAP:
            return _perr(429, "A code was just sent. Wait a minute before asking for another.",
                         {"resend_in": max(1, math.ceil(EC_RESEND_GAP - (now - last).total_seconds()))})
        sends = [x for x in (r.get("ec_sends") or []) if (_p := _parse_iso(x)) and (now - _p).total_seconds() < 3600]
        if len(sends) >= EC_MAX_SENDS_HOUR:
            return _perr(429, "Too many codes requested. Try again in an hour.", {})
        if not _rate_ok(f"ec-owner:{env['owner']}", EC_OWNER_DAY, 86400) or \
                not _rate_ok("ec-global", EC_GLOBAL_DAY, 86400):
            return _perr(429, "Too many codes have been requested right now. Please try again later.", {})
        code = f"{secrets.randbelow(10 ** 6):06d}"
        salt = _hex(8)
        r["ec_last_sent"] = _iso(now)              # the resend gap applies to failed sends too
        title = re.sub(r"\s+", " ", env.get("title") or "")[:80] or "documents"
        try:
            _send_mail(r["email"], f"Your signing code: {code}",
                       f"Your one-time code for the e-signature envelope titled\n\n    \"{title}\"\n\nis:"
                       f"\n\n    {code}\n\nIt expires in {EC_TTL // 60} minutes. Enter it only on the signing "
                       f"page you opened yourself. If you did not ask for it, ignore this email.\n\n— {brand.name()} "
                       f"(an automatic message; the envelope title above was written by its sender)")
        except Exception as e:
            _event(env, "email_code_failed", "system", meta, r["id"], {"note": f"email not sent ({type(e).__name__})"})
            _save(env)
            return _perr(502, "We couldn't send the email just now. Try again shortly.", {"resend_in": EC_RESEND_GAP})
        r.update({"ec_salt": salt, "ec_hash": _ac_hash(salt, code), "ec_expires": _iso(now + _dt.timedelta(
            seconds=EC_TTL)), "ec_fail": 0, "ec_last_sent": _iso(now), "ec_sends": sends + [_iso(now)]})
        _event(env, "email_code_sent", "system", meta, r["id"], {"note": f"one-time code emailed to "
                                                                          f"{_mask_email(r['email'])}"})
        _save(env)
        return JSONResponse(_session_view(env, r, False, "email_code"), headers=_PUB_HEADERS)


@router.post("/v1/sign/{token}/email-code/verify")
async def sign_email_code_verify(token: str, request: Request):
    _rate(request, "esign-ac", 20)
    raw = await _read_body(request, 2000)
    try:
        code = str((json.loads(raw or b"{}") or {}).get("code") or "").strip()
    except Exception:
        code = ""
    return await run_in_threadpool(_email_verify_sync, token, re.sub(r"\s+", "", code)[:12], _meta(request))


def _email_verify_sync(token: str, code: str, meta: dict):
    env, r = _resolve(token)
    if not env:
        return _perr(404, "This signing link is invalid or has been replaced.", {"state": "invalid"})
    with _lock(env["id"]):
        env, r = _resolve(token)
        if not env:
            return _perr(404, "This signing link is invalid or has been replaced.", {"state": "invalid"})
        gate = _pending_gate(env, r, meta)
        st = _state(env, r, gate is None, gate)
        if st != "email_code":
            return _perr(409, "No email code is needed right now.", {"state": st})
        now = _now_dt()
        if r.get("ec_locked"):
            return _perr(429, "This link has been locked after too many incorrect codes. Ask the sender for a new "
                              "link.", {"locked_until": "permanent", "attempts_left": 0})
        lock = _parse_iso(r.get("ec_lock_until"))
        if lock and lock > now:
            return _perr(429, "Too many incorrect codes. Try again later.", {"locked_until": r["ec_lock_until"],
                                                                           "attempts_left": 0})
        exp = _parse_iso(r.get("ec_expires"))
        if not r.get("ec_hash") or not exp or exp <= now:
            return _perr(410, "That code has expired. Ask for a new one.", {"code_sent": False})
        if code and hmac.compare_digest(_ac_hash(r.get("ec_salt") or "", code), r["ec_hash"]):
            r["ec_grant"] = _hex(8)
            r["ec_verified_at"] = _now()
            for k in ("ec_hash", "ec_salt", "ec_expires", "ec_fail"):
                r.pop(k, None)                    # single use
            _event(env, "email_code_ok", r.get("email") or "recipient", meta, r["id"],
                   {"note": "one-time email code confirmed"})
            _save(env)
            resp = JSONResponse({"ok": True}, headers=_PUB_HEADERS)
            resp.set_cookie(_ec_cookie_name(r), _ec_cookie_value(env["id"], r), max_age=12 * 3600, httponly=True,
                            secure=bool(meta.get("https")), samesite="strict", path="/v1/sign/" + token)
            return resp
        r["ec_fail"] = int(r.get("ec_fail") or 0) + 1
        r["ec_total_fail"] = int(r.get("ec_total_fail") or 0) + 1
        if r["ec_total_fail"] >= EC_HARD_LOCK:
            r["ec_locked"] = True
            for k in ("ec_hash", "ec_salt", "ec_expires", "ec_fail"):
                r.pop(k, None)
            _event(env, "email_code_failed", r.get("email") or "recipient", meta, r["id"],
                   {"note": f"link locked after {EC_HARD_LOCK} incorrect codes — the sender must issue a new link"})
            _save(env)
            return _perr(429, "This link has been locked after too many incorrect codes. Ask the sender for a new "
                              "link.", {"locked_until": "permanent", "attempts_left": 0})
        left = max(0, AC_MAX_FAILS - r["ec_fail"])
        extra = {"attempts_left": left}
        if left == 0:
            r["ec_lock_until"] = _iso(now + _dt.timedelta(seconds=AC_LOCK_SECS))
            for k in ("ec_hash", "ec_salt", "ec_expires", "ec_fail"):
                r.pop(k, None)                    # the code is burnt; a new one is needed after the lock
            extra["locked_until"] = r["ec_lock_until"]
        _event(env, "email_code_failed", r.get("email") or "recipient", meta, r["id"],
               {"note": "locked for 15 minutes" if left == 0 else f"{left} attempt(s) left"})
        _save(env)
        if left == 0:
            return _perr(429, "Too many incorrect codes. Try again in 15 minutes.", extra)
        return _perr(401, "That code isn't right.", extra)


@router.get("/v1/esign/config")
def esign_config(request: Request, caller: str = Depends(_caller)):
    """What this server's E-Sign can do (for the owner UI): email codes need SMTP; emailed links also need
    ESIGN_MAIL=1 and a known public URL (ESIGN_PUBLIC_URL, or a local development host); the seal needs a
    certificate."""
    st = SEAL.status()
    links = mail_available() and bool(_link_base(request, caller))
    return {"email_codes": smtp_configured(), "email_links": links,
            "email_from": _from_addr() if links else None,
            # names this account's remembered sender email in the browser (one browser, several accounts)
            "owner_key": hmac.new(_link_key(), f"owner|{caller}".encode(), hashlib.sha256).hexdigest()[:16],
            "identity": {"available": False, "reason": None},
            "link_key_configured": not _key_is_public_fallback(),
            "seal": {"configured": bool(st.get("configured")), "level": "PAdES-B-T" if st.get("configured") else None,
                     "cert_sha256": (st.get("cert") or {}).get("sha256"), "tsa": st.get("tsa"),
                     "expires_in_days": st.get("expires_in_days"), "expiring_soon": bool(st.get("expiring_soon")),
                     "problem": st.get("error")}}


def _active_or_err(env, r, meta, roles=ACTORS):
    gate = _pending_gate(env, r, meta)
    granted = gate is None
    st = _state(env, r, granted, gate)
    if st == "access_code":
        return None, _perr(401, "Enter the access code first.", {"state": "access_code"})
    if st == "email_code":
        return None, _perr(401, "Enter the code we emailed you first.", {"state": "email_code"})
    if st != "active" or r.get("role") not in roles:
        msg = {"waiting": "It isn't your turn to sign yet.", "done": "You've already completed this envelope.",
               "completed": "This envelope is already complete.", "voided": "This envelope has been voided.",
               "declined": "This envelope has been declined.", "expired": "This envelope has expired."}.get(st, "Not available.")
        return None, _perr(409, msg, {"state": st})
    return granted, None


@router.get("/v1/sign/{token}/pages/{did}/{n}.png")
def sign_page_png(token: str, did: str, n: int, request: Request, scale: float = 1.5):
    _rate(request, "esign-page", 300)
    env, r = _resolve(token)
    if not env:
        raise HTTPException(status_code=404, detail="not found", headers=_PUB_HEADERS)
    meta = _meta(request)
    gate = _pending_gate(env, r, meta)
    st = _state(env, r, gate is None, gate)
    if st not in ("active", "done", "completed"):
        raise HTTPException(status_code=403, detail="not available", headers=_PUB_HEADERS)
    d = _doc(env, did)
    if not d or n < 1 or n > int(d.get("page_count") or 0):
        raise HTTPException(status_code=404, detail="page not found", headers=_PUB_HEADERS)
    owner = env["owner"]
    bid = d.get("working_blob_id") or d["blob_id"]
    sc = _quant_scale(scale)
    return _png_response(request, lambda: _page_png(owner, bid, n - 1, sc), f'"{bid}-{n}-{sc}"', public=True)


@router.post("/v1/sign/{token}/consent")
def sign_consent(token: str, request: Request):
    _rate(request, "esign-act", 20)
    meta = _meta(request)
    env, r = _resolve(token)
    if not env:
        return _perr(404, "This signing link is invalid or has been replaced.", {"state": "invalid"})
    with _lock(env["id"]):
        env, r = _resolve(token)
        if not env:
            return _perr(404, "This signing link is invalid or has been replaced.", {"state": "invalid"})
        if _check_expiry(env):
            _save(env)
        granted, err = _active_or_err(env, r, meta)
        if err:
            return err
        if not r.get("consented_at"):
            r["consented_at"] = _now()
            _event(env, "consented", r.get("email") or "recipient", meta, r["id"],
                   {"note": "agreed to use electronic records and signatures"})
            _save(env)
    return JSONResponse(_session_view(env, r, granted), headers=_PUB_HEADERS)


@router.post("/v1/sign/{token}/decline")
async def sign_decline(token: str, request: Request):
    _rate(request, "esign-act", 20)
    raw = await _read_body(request, 4000)
    if raw is None:
        return _perr(413, "Request too large.")
    try:
        reason = _clean((json.loads(raw or b"{}") or {}).get("reason"), 500)
    except Exception:
        return _perr(400, "Invalid request.")
    if not reason:
        return _perr(422, "Please give a reason for declining.")
    return await run_in_threadpool(_decline_sync, token, reason, _meta(request))


def _decline_sync(token: str, reason: str, meta: dict):
    env, r = _resolve(token)
    if not env:
        return _perr(404, "This signing link is invalid or has been replaced.", {"state": "invalid"})
    with _lock(env["id"]):
        env, r = _resolve(token)
        if not env:
            return _perr(404, "This signing link is invalid or has been replaced.", {"state": "invalid"})
        if _check_expiry(env):
            _save(env)
        granted, err = _active_or_err(env, r, meta)
        if err:
            return err
        t = _now()
        r["status"], r["declined_at"], r["decline_reason"] = "declined", t, reason
        r["sign_ip"], r["sign_ua"] = meta.get("ip"), meta.get("ua")
        env["status"], env["current_order"] = "declined", None
        env["decline"] = {"recipient_id": r["id"], "reason": reason, "at": t}
        _event(env, "declined", r.get("email") or "recipient", meta, r["id"], {"note": reason})
        _queue_mail(env, "owner_declined", r["id"])
        _save(env)
    _public_log(env, r, "declined", meta)
    _kick(env)
    return JSONResponse(_session_view(env, r, granted), headers=_PUB_HEADERS)


_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@router.post("/v1/sign/{token}/complete")
async def sign_complete(token: str, request: Request):
    _rate(request, "esign-act", 20)
    raw = await _read_body(request, 6 * 1024 * 1024)
    if raw is None:
        return _perr(413, "Your submission is too large — try a simpler signature image.")
    try:
        data = json.loads(raw or b"{}")
        if not isinstance(data, dict):
            raise ValueError
    except Exception:
        return _perr(400, "Invalid request.")
    return await run_in_threadpool(_complete_sync, token, data, _meta(request))


def _complete_sync(token: str, data: dict, meta: dict):
    env, r = _resolve(token)
    if not env:
        return _perr(404, "This signing link is invalid or has been replaced.", {"state": "invalid"})
    with _lock(env["id"]):
        env, r = _resolve(token)
        if not env:
            return _perr(404, "This signing link is invalid or has been replaced.", {"state": "invalid"})
        if _check_expiry(env):
            _save(env)
        granted, err = _active_or_err(env, r, meta)
        if err:
            return err
        if not r.get("consented_at"):
            return _perr(409, "Please agree to use electronic records and signatures first.", {"state": "active"})
        owner, t = env["owner"], _now()
        new_blobs, old_blobs = [], []
        if r.get("role") == "viewer":
            r["status"], r["signed_at"], r["sign_ip"], r["sign_ua"] = "signed", t, meta.get("ip"), meta.get("ua")
            _event(env, "viewer_acknowledged", r.get("email") or "recipient", meta, r["id"],
                   {"note": f"{r.get('name')} confirmed they reviewed the documents"})
        else:
            try:
                stamps_by_doc, values, sig_png, ini_png = _collect_signer_input(env, r, data)
            except P.PdfError as e:
                return _perr(422, str(e))
            except ValueError as e:
                return _perr(422, str(e))
            try:
                for did, stamps in stamps_by_doc.items():
                    d = _doc(env, did)
                    cur = d.get("working_blob_id") or d["blob_id"]
                    flat = P.flatten(_get_blob(owner, cur), stamps)
                    nb = _put_blob(owner, env["id"], "working", flat, "application/pdf")
                    new_blobs.append(nb)
                    if d.get("working_blob_id"):
                        old_blobs.append(d["working_blob_id"])
                    d["working_blob_id"] = nb
                if sig_png:
                    r["sig_blob_id"] = _put_blob(owner, env["id"], "sig", sig_png, "image/png")
                    new_blobs.append(r["sig_blob_id"])
                if ini_png:
                    r["initials_blob_id"] = _put_blob(owner, env["id"], "initials", ini_png, "image/png")
                    new_blobs.append(r["initials_blob_id"])
            except Exception as e:
                for b in new_blobs:
                    _del_blob(owner, b)
                print("esign: stamping failed:", repr(e))
                return _perr(422, "This document couldn't be stamped. Please ask the sender to re-save it as a "
                                  "standard PDF and send it again.")
            for f in env.get("fields") or []:
                if f.get("recipient_id") == r["id"] and f["id"] in values:
                    f["value"] = values[f["id"]]
            r["status"], r["signed_at"], r["sign_ip"], r["sign_ua"] = "signed", t, meta.get("ip"), meta.get("ua")
            r["adopted_name"] = _clean(data.get("adopted_name"), 120) or r.get("name")
            _event(env, "signed", r.get("email") or "recipient", meta, r["id"],
                   {"note": f"{r.get('name')} signed ({sum(1 for v in values.values() if v not in (None, ''))} field(s))"})
        try:
            _advance(env, meta)
            if env.get("status") == "sent":         # the last one gets the completion note instead
                _queue_mail(env, "owner_signed", r["id"])
            _save(env)
        except Exception:
            # nothing was committed: drop what this request created; the stored envelope still points at the
            # previous (intact) working copies
            for b in new_blobs:
                _del_blob(owner, b)
            if (env.get("final") or {}).get("blob_id"):
                _del_blob(owner, env["final"]["blob_id"])
            raise
        for b in old_blobs:                       # only now is it safe to drop superseded working copies
            _del_blob(owner, b)
    _public_log(env, r, "signed", meta)
    _kick(env)
    return JSONResponse(_session_view(env, r, granted), headers=_PUB_HEADERS)


def _collect_signer_input(env: dict, r: dict, data: dict):
    """Validate a signer's submission and build per-document stamps. Raises ValueError / PdfError (user-safe)."""
    mine = [f for f in env.get("fields") or [] if f.get("recipient_id") == r["id"]]
    vals = data.get("values") or {}
    if not isinstance(vals, dict):
        raise ValueError("Invalid field values.")
    ids = {f["id"] for f in mine}
    for k in vals:
        if k not in ids:
            raise ValueError("Your submission includes a field that isn't yours.")
    stamps_in = data.get("stamps") or {}
    if not isinstance(stamps_in, dict):
        stamps_in = {}
    need_sig = any(f["type"] == "signature" and (f.get("required") or vals.get(f["id"])) for f in mine)
    need_ini = any(f["type"] == "initials" and (f.get("required") or vals.get(f["id"])) for f in mine)
    sig_png = P.image_from_data_url(data.get("signature")) if (need_sig and data.get("signature")) else None
    ini_png = P.image_from_data_url(data.get("initials")) if (need_ini and data.get("initials")) else None
    today = _now_dt().strftime("%Y-%m-%d")
    out_vals, stamps_by_doc, missing = {}, {}, []
    label = {"signature": "signature", "initials": "initials", "name": "name", "email": "email",
             "company": "company", "title": "title", "text": "text", "date": "date", "checkbox": "checkbox"}
    for f in mine:
        t, v = f["type"], vals.get(f["id"])
        v = "" if v is None else str(v)
        box = {"page": f["page"], "x": f["x"], "y": f["y"], "w": f["w"], "h": f["h"]}
        stamp = None
        if t == "signature":
            if sig_png and (v or f.get("required")):
                stamp, v = dict(box, kind="image", png=sig_png), "adopted"
            else:
                v = ""
        elif t == "initials":
            if ini_png and (v or f.get("required")):
                stamp, v = dict(box, kind="image", png=ini_png), "adopted"
            else:
                v = ""
        elif t == "date_signed":
            stamp, v = dict(box, kind="text", text=today), today
        elif t == "checkbox":
            v = "true" if v.lower() in ("true", "1", "yes", "on") else "false"
            if v == "true":
                stamp = dict(box, kind="check", checked=True)
            elif f.get("required"):
                missing.append(f)
        else:
            v = _clean(v, 500).replace("\n", " ")
            if t == "email":
                v = r.get("email") or ""            # never a signer-typed address
            if t == "date" and v and not _DATE.match(v):
                raise ValueError("Dates must be in YYYY-MM-DD format.")
            if v:
                if P.latin1_ok(v):
                    stamp = dict(box, kind="text", text=v)
                else:
                    img = stamps_in.get(f["id"])
                    if not img:
                        raise ValueError("Your browser didn't send a rendering for a non-Latin field — please try again.")
                    stamp = dict(box, kind="image", png=P.image_from_data_url(img, max_bytes=400 * 1024))
        if f.get("required") and t not in ("checkbox", "date_signed") and not v:
            missing.append(f)
        out_vals[f["id"]] = v
        if stamp:
            stamps_by_doc.setdefault(f["document_id"], []).append(stamp)
    if missing:
        kinds = sorted({label.get(f["type"], f["type"]) for f in missing})
        raise ValueError(f"Please complete all required fields ({len(missing)} left: {', '.join(kinds)}).")
    return stamps_by_doc, out_vals, sig_png, ini_png


@router.get("/v1/sign/{token}/download")
def sign_download(token: str, request: Request):
    _rate(request, "esign-dl", 20)
    env, r = _resolve(token)
    if not env:
        raise HTTPException(status_code=404, detail="not found", headers=_PUB_HEADERS)
    meta = _meta(request)
    if not _granted(env, r, meta):
        raise HTTPException(status_code=401, detail="Complete the sign-in checks first.", headers=_PUB_HEADERS)
    if env.get("status") != "completed" or not env.get("final"):
        raise HTTPException(status_code=409, detail="The signed document is available once everyone has signed.",
                            headers=_PUB_HEADERS)
    data = _get_blob(env["owner"], env["final"]["blob_id"])
    with _lock(env["id"]):
        fresh, rr = _resolve(token)
        if fresh:
            _event(fresh, "downloaded", rr.get("email") or "recipient", meta, rr["id"], {"note": "completed copy"})
            _save(fresh)
    resp = _attachment(data, "application/pdf", _safe_filename((env.get("title") or "document") + " - signed", ".pdf"))
    resp.headers.update({k: v for k, v in _PUB_HEADERS.items() if k != "Cache-Control"})
    return resp
