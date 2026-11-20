"""Test helpers: an in-memory document store with the same semantics as esign/store.py, so the E-Sign router can be
tested on a bare FastAPI app without the full server (auth, database)."""
import datetime as _dt
import hashlib
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class MemoryRepo:
    """Owner-scoped document store kept in a dict (mirrors store.py's methods)."""

    def __init__(self):
        self._docs = {}
        self.activity = []

    def log_activity(self, e: dict) -> None:
        self.activity.append(e)

    def store_document(self, data: bytes, content_type, caller, ip, parsed, owner=None) -> str:
        did = uuid.uuid4().hex
        self._docs[did] = {
            "id": did, "content_type": content_type, "data": data, "owner": owner,
            "ts": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sha256": hashlib.sha256(data).hexdigest(), "parsed": parsed}
        return did

    def get_document(self, doc_id: str, owner=None):
        d = self._docs.get(doc_id)
        if d and owner and d.get("owner") != owner:
            return None
        return d

    def get_document_review(self, doc_id: str, owner=None):
        d = self.get_document(doc_id, owner)
        return d.get("parsed") if d else None

    def update_document_review(self, doc_id: str, owner, patch: dict):
        d = self.get_document(doc_id, owner)
        if not d or not isinstance(d.get("parsed"), dict):
            return None
        d["parsed"].update(patch or {})
        return d["parsed"]

    def list_documents(self, owner, pipeline=None, limit=100):
        rows = [d for d in self._docs.values() if d.get("owner") == owner
                and (pipeline is None or (d.get("parsed") or {}).get("pipeline") == pipeline)]
        rows.sort(key=lambda d: d.get("ts") or "", reverse=True)
        return [{"id": d["id"], "ts": d.get("ts"), "review": d.get("parsed")} for d in rows[:limit]]

    def list_pipeline_owners(self, pipeline):
        return sorted({d.get("owner") for d in self._docs.values()
                       if (d.get("parsed") or {}).get("pipeline") == pipeline and d.get("owner")})

    def delete_document(self, doc_id: str, owner) -> bool:
        d = self._docs.get(doc_id)
        if not d or (owner and d.get("owner") != owner):
            return False
        self._docs.pop(doc_id, None)
        return True


def build_memory_repo() -> MemoryRepo:
    return MemoryRepo()


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch, tmp_path):
    """Every test starts with no seal / mail / brand settings, and a private data dir (no auto-generated PKI unless a
    test turns ESIGN_PKI_AUTO back on)."""
    import os
    for k in list(os.environ):
        if k.startswith("ESIGN_"):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ESIGN_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ESIGN_PKI_AUTO", "0")
    monkeypatch.setenv("ESIGN_SECRET", "test-secret")
    from esign import auth
    auth._limiter.clear()                           # sign-in / setup throttles count per process, not per test
    auth._known.clear()
    yield
