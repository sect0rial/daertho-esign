"""Storage: one table of owner-scoped documents (envelope JSON + file blobs), plus users, API keys and an activity log.

SQLite by default (a single file under ESIGN_DATA_DIR, fine for a team on one server with a disk). Set
ESIGN_DATABASE_URL=postgres://... to use Postgres instead. Both backends speak the same small interface that
esign.py relies on.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Optional


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_DDL = [
    """CREATE TABLE IF NOT EXISTS document (
        id TEXT PRIMARY KEY, owner TEXT, caller TEXT, ip TEXT, content_type TEXT, size_bytes INTEGER,
        sha256 TEXT, data {blob}, parsed TEXT, pipeline TEXT, ts TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS document_owner_pipe ON document (owner, pipeline, ts)",
    """CREATE TABLE IF NOT EXISTS app_user (
        id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT, role TEXT NOT NULL, pw_hash TEXT NOT NULL,
        created_at TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0, session_ver INTEGER NOT NULL DEFAULT 1)""",
    """CREATE TABLE IF NOT EXISTS api_key (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL, label TEXT, key_hash TEXT UNIQUE NOT NULL, prefix TEXT,
        created_at TEXT NOT NULL, last_used TEXT, revoked INTEGER NOT NULL DEFAULT 0)""",
    """CREATE TABLE IF NOT EXISTS activity (
        id TEXT PRIMARY KEY, ts TEXT NOT NULL, owner TEXT, event_type TEXT, payload TEXT)""",
]


class _Base:
    ph = "?"
    blob = "BLOB"

    # -- plumbing -------------------------------------------------------------------------------------------------
    def _exec(self, sql: str, args=(), fetch: str = ""):
        raise NotImplementedError

    def _q(self, sql: str) -> str:
        return sql.replace("?", self.ph)

    def init(self):
        for s in _DDL:
            self._exec(s.replace("{blob}", self.blob))

    # -- documents (the interface esign.py uses) ---------------------------------------------------------------------
    def store_document(self, data: bytes, content_type, caller, ip, parsed, owner=None) -> Optional[str]:
        did = uuid.uuid4().hex
        pipe = parsed.get("pipeline") if isinstance(parsed, dict) else None
        self._exec(self._q("INSERT INTO document (id,owner,caller,ip,content_type,size_bytes,sha256,data,parsed,"
                           "pipeline,ts) VALUES (?,?,?,?,?,?,?,?,?,?,?)"),
                   (did, owner, caller, ip, content_type, len(data), hashlib.sha256(data).hexdigest(), data,
                    json.dumps(parsed) if parsed is not None else None, pipe, _now()))
        return did

    def get_document(self, doc_id: str, owner=None):
        if owner:
            r = self._exec(self._q("SELECT content_type, data FROM document WHERE id=? AND owner=?"),
                           (doc_id, owner), "one")
        else:
            r = self._exec(self._q("SELECT content_type, data FROM document WHERE id=?"), (doc_id,), "one")
        return None if not r else {"content_type": r[0], "data": bytes(r[1] or b"")}

    def get_document_review(self, doc_id: str, owner=None):
        if owner:
            r = self._exec(self._q("SELECT parsed FROM document WHERE id=? AND owner=?"), (doc_id, owner), "one")
        else:
            r = self._exec(self._q("SELECT parsed FROM document WHERE id=?"), (doc_id,), "one")
        return json.loads(r[0]) if r and r[0] else None

    def update_document_review(self, doc_id: str, owner, patch: dict):
        with self._lock:
            parsed = self.get_document_review(doc_id, owner)
            if not isinstance(parsed, dict):
                return None
            parsed.update(patch or {})
            self._exec(self._q("UPDATE document SET parsed=?, pipeline=? WHERE id=? AND owner=?"),
                       (json.dumps(parsed), parsed.get("pipeline"), doc_id, owner))
            return parsed

    def list_documents(self, owner, pipeline=None, limit=100):
        if pipeline:
            rows = self._exec(self._q("SELECT id, ts, parsed FROM document WHERE owner=? AND pipeline=? "
                                      "ORDER BY ts DESC LIMIT ?"), (owner, pipeline, int(limit)), "all")
        else:
            rows = self._exec(self._q("SELECT id, ts, parsed FROM document WHERE owner=? ORDER BY ts DESC LIMIT ?"),
                              (owner, int(limit)), "all")
        return [{"id": r[0], "ts": r[1], "review": json.loads(r[2]) if r[2] else None} for r in rows]

    def list_pipeline_owners(self, pipeline):
        rows = self._exec(self._q("SELECT DISTINCT owner FROM document WHERE pipeline=? AND owner IS NOT NULL"),
                          (pipeline,), "all")
        return sorted(r[0] for r in rows)

    def delete_document(self, doc_id: str, owner) -> bool:
        if owner:
            n = self._exec(self._q("DELETE FROM document WHERE id=? AND owner=?"), (doc_id, owner), "count")
        else:
            n = self._exec(self._q("DELETE FROM document WHERE id=?"), (doc_id,), "count")
        return bool(n)

    def log_activity(self, e: dict) -> None:
        try:
            self._exec(self._q("INSERT INTO activity (id,ts,owner,event_type,payload) VALUES (?,?,?,?,?)"),
                       (uuid.uuid4().hex, _now(), e.get("owner") or e.get("caller"), e.get("event_type"),
                        json.dumps(e, default=str)[:20000]))
        except Exception as ex:                      # logging must never break a request
            print("activity log failed:", ex)

    # -- users ------------------------------------------------------------------------------------------------------
    _UCOLS = "id,email,name,role,pw_hash,created_at,disabled,session_ver"

    def _user(self, r):
        if not r:
            return None
        return dict(zip(self._UCOLS.split(","), r))

    def count_users(self) -> int:
        return int(self._exec("SELECT COUNT(*) FROM app_user", (), "one")[0])

    def create_user(self, email, name, role, pw_hash) -> dict:
        uid = uuid.uuid4().hex[:16]
        self._exec(self._q(f"INSERT INTO app_user ({self._UCOLS}) VALUES (?,?,?,?,?,?,0,1)"),
                   (uid, email, name, role, pw_hash, _now()))
        return self.get_user(uid)

    def create_first_admin(self, email, name, pw_hash) -> Optional[dict]:
        """The first-run admin: inserted only while the user table is empty, as ONE statement, so two first-run
        requests arriving together cannot both succeed. None = somebody already exists."""
        uid = uuid.uuid4().hex[:16]
        with self._lock:
            n = self._exec(self._q(f"INSERT INTO app_user ({self._UCOLS}) SELECT ?,?,?,?,?,?,0,1 "
                                   "WHERE NOT EXISTS (SELECT 1 FROM app_user)"),
                           (uid, email, name, "admin", pw_hash, _now()), "count")
        return self.get_user(uid) if n else None

    def get_user(self, uid):
        return self._user(self._exec(self._q(f"SELECT {self._UCOLS} FROM app_user WHERE id=?"), (uid,), "one"))

    def get_user_by_email(self, email):
        return self._user(self._exec(self._q(f"SELECT {self._UCOLS} FROM app_user WHERE email=?"), (email,), "one"))

    def list_users(self):
        return [self._user(r) for r in
                self._exec(f"SELECT {self._UCOLS} FROM app_user ORDER BY created_at", (), "all")]

    def update_user(self, uid, **fields):
        allowed = {k: v for k, v in fields.items() if k in ("name", "role", "pw_hash", "disabled", "session_ver")}
        if not allowed:
            return self.get_user(uid)
        sets = ",".join(f"{k}=?" for k in allowed)
        self._exec(self._q(f"UPDATE app_user SET {sets} WHERE id=?"), (*allowed.values(), uid))
        return self.get_user(uid)

    # -- API keys ---------------------------------------------------------------------------------------------------
    def create_key(self, user_id, label, key_hash, prefix) -> dict:
        kid = uuid.uuid4().hex[:16]
        self._exec(self._q("INSERT INTO api_key (id,user_id,label,key_hash,prefix,created_at,revoked) "
                           "VALUES (?,?,?,?,?,?,0)"), (kid, user_id, label, key_hash, prefix, _now()))
        return {"id": kid, "label": label, "prefix": prefix}

    def list_keys(self, user_id):
        rows = self._exec(self._q("SELECT id,label,prefix,created_at,last_used FROM api_key "
                                  "WHERE user_id=? AND revoked=0 ORDER BY created_at DESC"), (user_id,), "all")
        return [dict(zip(("id", "label", "prefix", "created_at", "last_used"), r)) for r in rows]

    def revoke_key(self, user_id, kid) -> bool:
        return bool(self._exec(self._q("UPDATE api_key SET revoked=1 WHERE id=? AND user_id=? AND revoked=0"),
                               (kid, user_id), "count"))

    def user_for_key(self, key_hash):
        r = self._exec(self._q("SELECT id,user_id FROM api_key WHERE key_hash=? AND revoked=0"), (key_hash,), "one")
        if not r:
            return None
        try:
            self._exec(self._q("UPDATE api_key SET last_used=? WHERE id=?"), (_now(), r[0]))
        except Exception:
            pass
        return self.get_user(r[1])


class SqliteStore(_Base):
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.RLock()
        self._local = threading.local()
        self.init()
        self._exec("PRAGMA journal_mode=WAL")

    def _conn(self):
        c = getattr(self._local, "c", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
            c.execute("PRAGMA busy_timeout=30000")
            self._local.c = c
        return c

    def _exec(self, sql, args=(), fetch=""):
        c = self._conn()
        with self._lock:
            cur = c.execute(sql, args)
            out = (cur.fetchone() if fetch == "one" else cur.fetchall() if fetch == "all"
                   else cur.rowcount if fetch == "count" else None)
            c.commit()
            return out


class PostgresStore(_Base):
    ph = "%s"
    blob = "BYTEA"

    def __init__(self, url: str):
        import psycopg                                 # optional dependency, only for Postgres deployments
        from psycopg_pool import ConnectionPool
        self._lock = threading.RLock()
        self.pool = ConnectionPool(url, min_size=1, max_size=int(os.environ.get("ESIGN_DB_POOL") or 8), open=True)
        self._psycopg = psycopg
        self.init()

    def _exec(self, sql, args=(), fetch=""):
        with self.pool.connection() as c, c.cursor() as cur:
            cur.execute(sql, args)
            out = (cur.fetchone() if fetch == "one" else cur.fetchall() if fetch == "all"
                   else cur.rowcount if fetch == "count" else None)
            c.commit()
            return out


def data_dir() -> Path:
    d = Path(os.environ.get("ESIGN_DATA_DIR") or "./data").resolve()
    d.mkdir(parents=True, exist_ok=True)
    return d


def open_store():
    url = (os.environ.get("ESIGN_DATABASE_URL") or "").strip()
    if url.startswith(("postgres://", "postgresql://")):
        return PostgresStore(url.replace("postgres://", "postgresql://", 1))
    if url.startswith("sqlite:///"):
        return SqliteStore(url[len("sqlite:///"):])
    return SqliteStore(str(data_dir() / "esign.db"))
