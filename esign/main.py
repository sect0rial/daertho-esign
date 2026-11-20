"""Daertho E-Sign — app entry point.

    uvicorn esign.main:app --host 0.0.0.0 --port 8000

Run ONE worker process: envelope edits are serialised with in-process locks.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import re
import secrets
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import auth, brand, esign, esign_pdf, limits, net, store

STATIC = Path(__file__).resolve().parent / "static"
VERSION = "0.1.0"


def _secret() -> bytes:
    s = (os.environ.get("ESIGN_SECRET") or "").strip()
    if s:
        if len(s) < 32:
            sys.exit("ESIGN_SECRET must be at least 32 characters (try: openssl rand -hex 32)")
        return hashlib.sha256(b"esign-session|" + s.encode()).digest()
    if os.environ.get("ESIGN_ENV") == "production":
        sys.exit("ESIGN_SECRET is required when ESIGN_ENV=production (try: openssl rand -hex 32)")
    # Development: keep a generated secret in the data dir so sessions and links survive restarts.
    f = store.data_dir() / ".dev-secret"
    if not f.exists():
        f.write_text(secrets.token_hex(32))
        f.chmod(0o600)
        print("WARNING: ESIGN_SECRET is not set — using a generated development secret in", f)
    os.environ.setdefault("ESIGN_SECRET", f.read_text().strip())
    return hashlib.sha256(b"esign-session|" + os.environ["ESIGN_SECRET"].encode()).digest()


SECRET = _secret()
STORE = store.open_store()
auth.configure(STORE, SECRET)
auth.init_setup_token(store.data_dir())             # fresh deployment: the first-run page needs this token


def _log_activity(request, event_type, caller, payload=None, response=None):
    STORE.log_activity({"event_type": event_type, "caller": caller, "owner": caller,
                        "payload": payload if isinstance(payload, (dict, list, str, int, float)) else None})


def _owner_profile(owner: str) -> dict:
    u = STORE.get_user(owner[2:]) if str(owner).startswith("u:") else None
    return {"name": u["name"] or "", "email": u["email"]} if u else {}


esign.configure(lambda: STORE, require_key=auth.require_key, session_label=auth.session_label,
                log_activity=_log_activity, owner_profile=_owner_profile)

try:
    esign.check_enc_key()                           # a mistyped key must stop the server, not switch encryption off
except esign.EncKeyError as e:
    sys.exit(str(e))

if hasattr(esign, "ensure_pki"):
    esign.ensure_pki(store.data_dir())


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    task = None
    if esign.mail_available():
        async def _mail_loop():
            await asyncio.sleep(15)
            while True:
                try:
                    n = await asyncio.to_thread(esign.deliver_due)
                    if n:
                        print(f"esign: {n} queued email(s) sent")
                except Exception as e:                # keep the loop alive; the outbox retries
                    print(f"esign email delivery failed: {type(e).__name__}: {e}")
                await asyncio.sleep(60)
        task = asyncio.create_task(_mail_loop())
    yield
    if task:
        task.cancel()


# The interactive API docs load Swagger UI from a public CDN. ESIGN_API_DOCS=0 switches them (and /openapi.json) off.
API_DOCS = (os.environ.get("ESIGN_API_DOCS") or "1").strip() != "0"
app = FastAPI(title=brand.name(), version=VERSION, lifespan=lifespan, redoc_url=None,
              docs_url="/api/docs" if API_DOCS else None, openapi_url="/openapi.json" if API_DOCS else None)

# The owner app is plain files from this origin: no inline or third-party script may run in it. Styles and fonts
# may come from Google Fonts (brand fonts); images may be the brand logo (any https URL) and in-page previews.
APP_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
           "font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: blob: https:; connect-src 'self'; "
           "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


# ---- request-body limits (see limits.py): checked before the body is read, and before it is parsed to disk ----
def _env_mb(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name) or default)) * limits.MB
    except ValueError:
        sys.exit(f"{name} must be a whole number of megabytes")


MAX_BODY = _env_mb("ESIGN_MAX_BODY_MB", 8)                                        # any request not listed below
MAX_AUTH_BODY = 64 * 1024                                                         # sign-in, setup, users, keys
_DOC_UPLOAD = re.compile(r"^/v1/esign/envelopes/[^/]+/documents$")


def _body_rule(method: str, path: str):
    """(max body bytes, needs a signed-in user) for a request. Every /v1/esign/ route is an owner route."""
    if path.startswith("/v1/esign/"):
        if method == "POST" and path == "/v1/esign/verify":
            return esign.verify_max_bytes() + limits.MARGIN, True
        if method == "POST" and _DOC_UPLOAD.match(path):
            return esign_pdf.MAX_FILE_BYTES + limits.MARGIN, True
        return MAX_BODY, True
    if path.startswith("/v1/auth/"):
        return MAX_AUTH_BODY, False
    return MAX_BODY, False


def _signed_in(request: Request):
    """None if the request carries a valid session or API key, else the (status, message) to answer with."""
    try:
        user = auth.current_user(request, request.headers.get("x-api-key"))
    except HTTPException as e:
        return e.status_code, str(e.detail)
    return None if user else (401, "Sign in first.")


# Added before the security-headers middleware below, so it runs inside it and its answers carry those headers too.
app.add_middleware(limits.BodyLimitMiddleware, rule=_body_rule, authenticate=_signed_in)


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    resp: Response = await call_next(request)
    h = resp.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("Referrer-Policy", "same-origin")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if net.is_https(request):
        h.setdefault("Strict-Transport-Security", "max-age=31536000")
    return resp


app.include_router(brand.router)
app.include_router(auth.router)
app.include_router(esign.router)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(STATIC / "app.html", headers={"Cache-Control": "no-cache", "Content-Security-Policy": APP_CSP})


@app.get("/favicon.svg", include_in_schema=False)
@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse(STATIC / "favicon.svg", media_type="image/svg+xml")


@app.get("/healthz", include_in_schema=False)
def healthz():
    try:
        STORE.count_users()
    except Exception as e:
        return JSONResponse({"ok": False, "error": type(e).__name__}, status_code=503)
    return {"ok": True, "version": VERSION}
