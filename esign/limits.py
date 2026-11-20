"""Request-body limits, applied before a single byte of the body is read or parsed.

FastAPI parses a multipart upload (spooling each file to a temp file on disk) BEFORE it runs the route's
dependencies, so a size check or a sign-in check inside a handler comes too late: the whole body is already on
disk. This middleware sits in front of the router and, per request:

1. refuses a Content-Length above the route's limit (413) without reading anything;
2. on routes that need a signed-in user, checks the session cookie / API key first (401 before the body is read);
3. counts the bytes actually received, so a chunked body with no Content-Length is cut off at the same limit.
"""
from __future__ import annotations

import json
from typing import Callable, Optional, Tuple

from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers
from starlette.requests import Request

MB = 1024 * 1024
MARGIN = MB                                          # multipart boundaries and part headers on top of the file


class _BodyTooLarge(Exception):
    pass


class BodyLimitMiddleware:
    """rule(method, path) -> (max body bytes, needs sign-in).
    authenticate(request) -> None when the caller is signed in, else (status, message)."""

    def __init__(self, app, rule: Callable[[str, str], Tuple[int, bool]],
                 authenticate: Optional[Callable[[Request], Optional[Tuple[int, str]]]] = None):
        self.app, self.rule, self.authenticate = app, rule, authenticate

    @staticmethod
    async def _reply(send, status: int, detail: str):
        body = json.dumps({"detail": detail}).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode()),
                                (b"cache-control", b"no-store"), (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit, needs_auth = self.rule(scope.get("method", ""), scope.get("path", ""))
        too_large = f"That request is too large (the limit here is {max(1, limit // MB)} MB)."
        headers = Headers(scope=scope)
        declared = headers.get("content-length")
        if declared is not None:
            if not declared.isdigit():
                return await self._reply(send, 400, "Invalid Content-Length.")
            if int(declared) > limit:
                return await self._reply(send, 413, too_large)
            has_body = int(declared) > 0
        else:
            has_body = "chunked" in (headers.get("transfer-encoding") or "").lower()
        if has_body and needs_auth and self.authenticate is not None:
            problem = await run_in_threadpool(self.authenticate, Request(scope))
            if problem:
                return await self._reply(send, problem[0], problem[1])

        seen, cut, started = 0, False, False

        async def limited_receive():
            nonlocal seen, cut
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body") or b"")
                if seen > limit:
                    cut = True
                    raise _BodyTooLarge()
            return message

        async def guarded_send(message):
            nonlocal started
            if cut:
                return                               # whatever the app says after the cut-off, the answer is 413
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except _BodyTooLarge:
            pass
        if cut and not started:
            await self._reply(send, 413, too_large)
