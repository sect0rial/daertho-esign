"""Who is calling, and how often: the client address (proxy-aware) and bounded sliding-window counters.

Both the envelope router (signer evidence, per-address limits on the public signing routes) and the account routes
(sign-in and first-run limits) use these, so there is exactly one rule for which address a request counts as.
"""
from __future__ import annotations

import ipaddress
import os
import re
import threading
import time
from collections import OrderedDict, deque

_ADDR = re.compile(r"^[0-9A-Fa-f:.]{2,45}$")


def trust_proxy() -> bool:
    return (os.environ.get("ESIGN_TRUST_PROXY") or "").strip() == "1"


def client_ip(request) -> str:
    """The visitor's IP. With ESIGN_TRUST_PROXY=1 (only when the app is reachable solely through your own reverse
    proxy / platform router): the LAST X-Forwarded-For hop, the one that proxy wrote — never a left-hand hop or a
    CF-Connecting-IP header the client could have sent itself. Otherwise the TCP peer address."""
    if request is None:
        return ""
    if trust_proxy():
        xff = (request.headers.get("x-forwarded-for") or "").split(",")[-1].strip()
        if xff and _ADDR.match(xff):
            return xff
    try:
        return (request.client.host if request.client else "") or ""
    except Exception:
        return ""


def limit_key(ip: str) -> str:
    """What per-IP rate limits count by: the IPv4 address, or the IPv6 /64 (one host usually owns a whole /64)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip or "unknown"
    if a.version == 6:
        if a.ipv4_mapped:
            return str(a.ipv4_mapped)
        return str(ipaddress.ip_network(f"{a}/64", strict=False))
    return str(a)


class Window:
    """Sliding-window counters kept in memory, bounded two ways: at most `max_keys` keys (the least recently used
    are dropped first) and at most `max_hits` timestamps per key. Keys are caller-chosen strings, some of them built
    from what a stranger typed, so neither may grow without limit."""

    def __init__(self, max_keys: int = 20000, max_hits: int = 1000):
        self._d: "OrderedDict[str, deque]" = OrderedDict()
        self._lock = threading.Lock()
        self._max_keys, self._max_hits = max_keys, max_hits

    def _q(self, key: str, window: float, now: float, create: bool):
        q = self._d.get(key)
        if q is None:
            if not create:
                return None
            q = self._d[key] = deque(maxlen=self._max_hits)
            while len(self._d) > self._max_keys:
                self._d.popitem(last=False)
        else:
            self._d.move_to_end(key)
        while q and q[0] <= now - window:
            q.popleft()
        return q

    def count(self, key: str, window: float) -> int:
        """Hits recorded for `key` in the last `window` seconds."""
        with self._lock:
            q = self._q(key, window, time.time(), False)
            if q is not None and not q:
                self._d.pop(key, None)
            return len(q) if q else 0

    def add(self, key: str, window: float) -> None:
        """Record one hit."""
        with self._lock:
            now = time.time()
            self._q(key, window, now, True).append(now)

    def hit(self, key: str, limit: int, window: float) -> bool:
        """Record one hit if fewer than `limit` happened in the window. False = over the limit (nothing recorded)."""
        with self._lock:
            now = time.time()
            q = self._q(key, window, now, True)
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def clear(self, key=None) -> None:
        with self._lock:
            if key is None:
                self._d.clear()
            else:
                self._d.pop(key, None)

    def __len__(self) -> int:
        return len(self._d)
