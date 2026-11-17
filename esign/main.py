"""Daertho E-Sign — app entry point.

    uvicorn esign.main:app --host 0.0.0.0 --port 8000

Run ONE worker process: envelope edits are serialised with in-process locks.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import secrets
import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import auth, brand, esign, store

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


def _log_activity(request, event_type, caller, payload=None, response=None):
    STORE.log_activity({"event_type": event_type, "caller": caller, "owner": caller,
                        "payload": payload if isinstance(payload, (dict, list, str, int, float)) else None})


esign.configure(lambda: STORE, require_key=auth.require_key, session_label=auth.session_label,
                log_activity=_log_activity)

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


app = FastAPI(title=brand.name(), version=VERSION, lifespan=lifespan, docs_url="/api/docs", redoc_url=None)


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    resp: Response = await call_next(request)
    h = resp.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("Referrer-Policy", "same-origin")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.url.scheme == "https" or (os.environ.get("ESIGN_PUBLIC_URL") or "").startswith("https://"):
        h.setdefault("Strict-Transport-Security", "max-age=31536000")
    return resp


app.include_router(brand.router)
app.include_router(auth.router)
app.include_router(esign.router)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(STATIC / "app.html", headers={"Cache-Control": "no-cache"})


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
